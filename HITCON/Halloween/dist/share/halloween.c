#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/net.h>
#include <linux/in.h>
#include <linux/socket.h>
#include <linux/slab.h>
#include <linux/kthread.h>
#include <linux/skbuff.h>
#include <linux/uaccess.h>
#include <linux/list.h>
#include <linux/delay.h>
#include <linux/timekeeping.h>
#include <linux/random.h>
#include <linux/spinlock.h>
#include <linux/refcount.h>
#include <linux/mutex.h>
#include <linux/reboot.h>

#define EXPIRE_PERIOD 1
#define SPACE_ALIGNMENT 4
#define TOT_MAGIC (0x3133303121746f74L)

#define TT_PING (0)
#define TT_REGISTER (1)
#define TT_AUTH (2)
#define TT_READ (3)
#define TT_WRITE (4)
#define TT_UPDATE_SECRET (5)

enum grip_state {
    GS_GUEST = 0,
    GS_AUTHING,
    GS_ADMIN,
};

struct trick {
    unsigned long magic;
    unsigned long type;
};

#define MAX_SCARECROW_SPACE 0x80
struct scarecrow {
    char *name;
    char *secret;
    unsigned char name_len;
    unsigned char secret_len;
    struct mutex lock;

    struct list_head list;
    unsigned short curr_ptr;
    unsigned int total_size;
    unsigned int space_size;
    char space[];
};

struct grip {
    struct scarecrow *scarecrow;
    struct timespec64 expired_ts;
    unsigned long cookie;
    refcount_t refcnt;

    enum grip_state state;
    struct trick trick;
};

struct grip_request {
    int id;
    struct socket *sock;
};

#define MAX_SCARECROW_COUNT 32
#define MAX_GRIP_COUNT 4
static struct task_struct *accept_thread = NULL;
static struct socket *server_sock;
static struct list_head scarecrow_head;
static struct grip *grips[MAX_GRIP_COUNT];
static int tids[MAX_GRIP_COUNT];

static DEFINE_MUTEX(grips_lock);
static DEFINE_MUTEX(scarecrow_lock);

static atomic_t grip_count;
static atomic_t scarecrow_count;

static int read_from_socket(struct socket *sock, void *buf, int size, int flags)
{
    struct msghdr msg;
    struct kvec vec;
    int ret;

    vec.iov_base = buf;
    vec.iov_len = size;
    
    for (int i = 0; i < 10; i++) {
        ret = kernel_recvmsg(sock, &msg, &vec, 1, size, flags);
        if (ret == -EAGAIN || ret == -EWOULDBLOCK) {
            ret = 1;
            continue;
        }
        
        if (ret <= 0 || ret != size) {
            ret = -1;
            break;
        }

        ret = 0;
        break;
    }

    return ret;
}

static int send_to_socket(struct socket *sock, void *buf, int size)
{
    struct msghdr msg;
    struct kvec vec;
    int ret;

    vec.iov_base = buf;
    vec.iov_len = size;
    
    ret = kernel_sendmsg(sock, &msg, &vec, 1, size);
    if (ret < 0)
        return ret;

    if (ret != size)
        return -EINVAL;

    return 0;
}

static struct scarecrow *lookup_scarecrow(char *name, unsigned char name_len)
{
    struct scarecrow *scarecrow_iter;

    mutex_lock(&scarecrow_lock);
    list_for_each_entry(scarecrow_iter, &scarecrow_head, list) {
        if (scarecrow_iter->name_len == name_len &&
            !memcmp(scarecrow_iter->name, name, name_len))
            goto found;
    }
    scarecrow_iter = NULL;
found:
    mutex_unlock(&scarecrow_lock);
    return scarecrow_iter;
}

static inline void reset_grips(void)
{
    for (int i = 0; i < MAX_GRIP_COUNT; i++)
        grips[i] = NULL;
}

static struct grip *lookup_grip(unsigned long cookie)
{
    struct grip *grip = NULL;

    mutex_lock(&grips_lock);
    for (int i = 0; i < MAX_GRIP_COUNT; i++) {
        if (grips[i] && grips[i]->cookie == cookie) {
            grip = grips[i];
            refcount_inc(&grip->refcnt);
            break;
        }
    }
    mutex_unlock(&grips_lock);
    return grip;
}

static void save_grip(struct grip *grip)
{
    int slot = -1;
    int i;

    mutex_lock(&grips_lock);
    for (i = 0; i < MAX_GRIP_COUNT; i++) {
        if (!grips[i] && slot == -1) {
            slot = i;
            break;
        }
    }

    if (i == MAX_GRIP_COUNT || slot == -1) {
        reset_grips();
        grips[0] = grip;
    } else {
        grips[slot] = grip;
    }
    mutex_unlock(&grips_lock);
}

static int register_trick(struct socket *sock)
{
    int count;
    int success = 0;
    int err;
    void *data;
    struct scarecrow *new_scarecrow;
    struct register_trick {
        unsigned char name_len;
        unsigned char secret_len;
        unsigned short space_size;
    } reg_trick;

    count = atomic_inc_return(&scarecrow_count);
    if (count > MAX_SCARECROW_COUNT) {
        atomic_dec(&scarecrow_count);
        return -1;
    }

    err = read_from_socket(sock, &reg_trick, sizeof(struct register_trick), 0);
    if (err != 0) {
        err = -1;
        goto bad;
    }

    if (reg_trick.space_size > MAX_SCARECROW_SPACE) {
        err = -1;
        goto bad;
    }

    new_scarecrow = kzalloc(sizeof(struct scarecrow) + reg_trick.space_size, GFP_KERNEL);
    if (!new_scarecrow) {
        err = -1;
        goto bad;
    }

    data = kmalloc(reg_trick.name_len + reg_trick.secret_len, GFP_KERNEL);
    if (!data) {
        err = -1;
        goto free_scarecrow;
    }

    err = read_from_socket(sock, data, reg_trick.name_len + reg_trick.secret_len, 0);
    if (err != 0) {
        err = -1;
        goto free_data;
    }
    
    if (!strncmp(data, "root", 4)) {
        err = -1;
        goto free_data;
    }

    new_scarecrow->name = data;
    new_scarecrow->name_len = reg_trick.name_len;
    new_scarecrow->secret = data + reg_trick.name_len;
    new_scarecrow->secret_len = reg_trick.secret_len;
    INIT_LIST_HEAD(&new_scarecrow->list);
    mutex_init(&new_scarecrow->lock);

    new_scarecrow->space_size = reg_trick.space_size;
    new_scarecrow->curr_ptr = 0;
    new_scarecrow->total_size = 0;
    
    mutex_lock(&scarecrow_lock);
    list_add(&new_scarecrow->list, &scarecrow_head);
    mutex_unlock(&scarecrow_lock);
    
    err = 0;
    success = 1;
    goto good;

free_data:
    kfree(data);
free_scarecrow:
    kfree(new_scarecrow);
bad:
    atomic_dec(&scarecrow_count);
good:
    send_to_socket(sock, &success, sizeof(success));
    return err;
}

static int auth_trick(struct socket *sock, struct grip *grip)
{
    int success = 0;
    int err;
    void *data;
    struct scarecrow *scarecrow;
    struct auth_trick {
        unsigned char name_len;
        unsigned char secret_len;
    } auth_trick;

    if (grip->state == GS_AUTHING)
        return -1;
    
    mutex_lock(&grips_lock);
    grip->state = GS_AUTHING;

    err = read_from_socket(sock, &auth_trick, sizeof(struct auth_trick), 0);
    if (err != 0) {
        err = -1;
        goto unlock;
    }

    data = kmalloc(auth_trick.name_len + auth_trick.secret_len, GFP_KERNEL);
    if (!data) {
        err = -1;
        goto unlock;
    }

    err = read_from_socket(sock, data, auth_trick.name_len + auth_trick.secret_len, 0);
    if (err != 0)  {
        err = -1;
        goto release;
    }

    scarecrow = lookup_scarecrow(data, auth_trick.name_len);
    if (scarecrow != NULL &&
        !memcmp(scarecrow->secret, data + auth_trick.name_len, auth_trick.secret_len)) {
        success = 1;
        grip->scarecrow = scarecrow;
        if (!strncmp(scarecrow->name, "root", scarecrow->name_len))
            grip->state = GS_ADMIN;
        else
            grip->state = GS_GUEST;
    }
    err = 0;

release:
    kfree(data);
unlock:
    if (grip->state == GS_AUTHING)
        grip->state = GS_GUEST;
    mutex_unlock(&grips_lock);
    send_to_socket(sock, &success, sizeof(success));
    return err;
}

static inline void reset_expired_ts(struct grip *grip)
{
    ktime_get_real_ts64(&grip->expired_ts);
    grip->expired_ts.tv_sec += EXPIRE_PERIOD;
}

static int read_trick(struct socket *sock, struct grip *grip)
{
    int err;
    char iter;
    char aligned_size;
    char content_len;
    char curr_size;
    char next_iter;
    void *base;
    void *space;
    struct scarecrow *scarecrow;
    struct read_trick {
        char read_length;
    } rtrick;

    scarecrow = grip->scarecrow;
    if (!scarecrow || grip->state != GS_ADMIN)
        return 0;

    err = read_from_socket(sock, &rtrick, sizeof(struct read_trick), 0);
    if (err != 0)
        return -1;

    if (rtrick.read_length > scarecrow->total_size)
        return -1;

    base = kmalloc(rtrick.read_length, GFP_KERNEL);
    if (!base)
        return -1;
    
    space = &scarecrow->space[0];
    iter = curr_size = 0;

    while (iter + 1 < scarecrow->curr_ptr) {

        content_len = *(char *)space;
        if (content_len < 0)
            break;

        if (content_len >= rtrick.read_length - curr_size)
            content_len = rtrick.read_length - curr_size;
        
        next_iter = iter + 1 + content_len;
        if (next_iter >= scarecrow->curr_ptr)
            break;

        memcpy(base + curr_size, space + 1, content_len);
        curr_size += content_len;

        if (curr_size == rtrick.read_length)
            break;

        aligned_size = ALIGN(1 + content_len, SPACE_ALIGNMENT);
        iter += aligned_size;
        space += aligned_size;
    }

    send_to_socket(sock, base, curr_size);
    kfree(base);
    return 0;
}

static int write_trick(struct socket *sock, struct grip *grip)
{
    int success = 0;
    int err;
    unsigned int next_size;
    struct scarecrow *scarecrow;
    struct write_trick {
        char content_len;
    } wtrick;

    scarecrow = grip->scarecrow;
    if (!scarecrow || grip->state != GS_ADMIN)
        return 0;

    err = read_from_socket(sock, &wtrick, sizeof(struct write_trick), 0);
    if (err != 0)
        return -1;

    mutex_lock(&scarecrow->lock);
    if (scarecrow->curr_ptr >= scarecrow->space_size) {
        err = 0;
        goto unlock;
    }

    if (!wtrick.content_len || wtrick.content_len > scarecrow->space_size) {
        err = -1;
        goto unlock;
    }

    next_size = ALIGN(scarecrow->curr_ptr + wtrick.content_len + 1, SPACE_ALIGNMENT);
    if (next_size > scarecrow->space_size) {
        err = -1;
        goto unlock;
    }

    *(char *)&scarecrow->space[scarecrow->curr_ptr] = wtrick.content_len;
    scarecrow->curr_ptr += 1;

    err = read_from_socket(sock, &scarecrow->space[scarecrow->curr_ptr], wtrick.content_len, 0);
    if (err != 0) {
        err = -1;
        goto unlock;
    }
    
    success = 1;
    scarecrow->total_size += wtrick.content_len;
    scarecrow->curr_ptr = next_size;

unlock:
    mutex_unlock(&scarecrow->lock);
    send_to_socket(sock, &success, sizeof(success));
    return err;
}

static int update_secret_trick(struct socket *sock, struct grip *grip)
{
    int err;
    struct scarecrow *scarecrow;
    void *new_secret;

    scarecrow = grip->scarecrow;
    if (!scarecrow)
        return 0;

    new_secret = kmalloc(scarecrow->secret_len, GFP_KERNEL);
    if (!new_secret) {
        return -1;
    }

    err = read_from_socket(sock, new_secret, scarecrow->secret_len, 0);
    if (err != 0)  {
        err = -1;
        goto release;
    }
    memcpy(scarecrow->secret, new_secret, scarecrow->secret_len);
    err = 0;

release:
    kfree(new_secret);
    return err;
}

static int handle_trick(void *data)
{
    int id;
    int err;
    struct socket *sock;
    unsigned long cookie;
    struct timespec64 curr_ts;
    struct grip *grip = NULL;
    struct grip_request *grip_req = data;

    id = grip_req->id;
    sock = grip_req->sock;
    kfree(grip_req);

    err = read_from_socket(sock, &cookie, sizeof(cookie), 0);
    if (err < 0)
        goto ret;

    if (cookie) {
        grip = lookup_grip(cookie);
    }
    
    if (!grip) {
        grip = kmalloc(sizeof(struct grip), GFP_KERNEL);
        if (!grip)
            goto ret;
        
        grip->scarecrow = NULL;
        grip->state = GS_GUEST;
        refcount_set(&grip->refcnt, 1);
        reset_expired_ts(grip);

        if (cookie)
            grip->cookie = cookie;
        else
            get_random_bytes(&grip->cookie, sizeof(unsigned long));
        
        save_grip(grip);
        pr_info("[*] create grip with cookie %016lx\n", grip->cookie);
    } else {
        pr_info("[*] reuse old grip with cookie %016lx\n", grip->cookie);
    }
    send_to_socket(sock, &grip->cookie, sizeof(unsigned long));

    while (true) {
        while (true) {
            err = read_from_socket(sock, &grip->trick, sizeof(struct trick), MSG_DONTWAIT);
            if (err == -1)
                break;

            if (err == 0) {
                if (grip->trick.magic != TOT_MAGIC || grip->trick.type > TT_UPDATE_SECRET)
                    continue;
                break;
            }

            msleep(5);
            ktime_get_real_ts64(&curr_ts);
            if (curr_ts.tv_sec > grip->expired_ts.tv_sec) {
                pr_info("[*] connection expire %016lx\n", grip->cookie);
                err = -1;
                break;
            }
        }

        if (err == -1)
            break;
        
        reset_expired_ts(grip);
        switch (grip->trick.type) {
        case TT_PING:
            send_to_socket(sock, "PONG", 4);
            break;

        case TT_REGISTER:
            err = register_trick(sock);
            break;

        case TT_AUTH:
            err = auth_trick(sock, grip);
            break;

        case TT_READ:
            err = read_trick(sock, grip);
            break;

        case TT_WRITE:
            err = write_trick(sock, grip);
            break;

        case TT_UPDATE_SECRET:
            err = update_secret_trick(sock, grip);
            break;
        
        default:
            __builtin_unreachable();
        }

        if (err < 0)
            break;
    }

    mutex_lock(&grips_lock);
    reset_grips();
    mutex_unlock(&grips_lock);
    
    pr_info("[*] disconnect cookie %016lx\n", grip->cookie);
    if (refcount_dec_and_test(&grip->refcnt))
        kfree(grip);
ret:
    sock_release(sock);
    atomic_dec(&grip_count);
    tids[id] = 0;
    return 0;
}

static int acceptd(void *data)
{
    int i;
    int err;
    int count;
    struct socket *newsock;
    struct task_struct *grip_thread;
    struct grip_request *grip_req;
    
    while (true) {
        err = kernel_accept(server_sock, &newsock, 0);
        if (err < 0) {
            if (err == -EAGAIN || err == -EINTR) {
                continue;
            }
            pr_err("Accept error\n");
            break;
        }
        
        count = atomic_inc_return(&grip_count);
        if (count > MAX_GRIP_COUNT) {
            atomic_set(&grip_count, MAX_GRIP_COUNT);
            sock_release(newsock);
            pr_info("Too many grips, reject it\n");
            continue;
        }

        for (i = 0; i < MAX_GRIP_COUNT; i++)
            if (tids[i] == 0)
                break;
        tids[i] = 1;
        
        grip_req = kmalloc(sizeof(struct grip_request), GFP_KERNEL);
        if (!grip_req)
            break;

        grip_req->id = i;
        grip_req->sock = newsock;
        grip_thread = kthread_run(handle_trick, grip_req, "grip-thread-%d", count);
        if (IS_ERR(grip_thread)) {
            sock_release(newsock);
            atomic_dec(&grip_count);
            pr_err("Failed to create grip thread\n");
        }
    }

    orderly_poweroff(true);
    return 0;
}

static int __init halloween_init(void)
{
    struct sockaddr_in addr;
    int err;

    pr_info("Initializing Halloween...\n");

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(1337);

    err = sock_create(PF_INET, SOCK_STREAM, IPPROTO_TCP, &server_sock);
    if (err < 0) {
        pr_err("Failed to create socket\n");
        return err;
    }

    err = kernel_bind(server_sock, (struct sockaddr *)&addr, sizeof(addr));
    if (err < 0) {
        pr_err("Failed to bind socket\n");
        sock_release(server_sock);
        return err;
    }

    err = kernel_listen(server_sock, 1);
    if (err < 0) {
        pr_err("Failed to listen on socket\n");
        sock_release(server_sock);
        return err;
    }

    accept_thread = kthread_run(acceptd, NULL, "accept_thread");
    if (IS_ERR(accept_thread)) {
        pr_err("Failed to create accept thread\n");
        sock_release(server_sock);
        return PTR_ERR(accept_thread);
    }

    atomic_set(&scarecrow_count, 0);
    atomic_set(&grip_count, 0);
    INIT_LIST_HEAD(&scarecrow_head);

    pr_info("Halloween Service is running now\n");
    return 0;
}

static void __exit halloween_exit(void)
{
    if (accept_thread) {
        kthread_stop(accept_thread);
        accept_thread = NULL;
    }

    if (server_sock) {
        sock_release(server_sock);
        server_sock = NULL;
    }
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Pumpkin");
MODULE_DESCRIPTION("Halloween");
MODULE_VERSION("1.0");

module_init(halloween_init);
module_exit(halloween_exit);