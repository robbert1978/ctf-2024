define debug_proc
    set sysroot /proc/$arg0/root
    file /proc/$arg0/root/app/web
    attach $arg0
end
