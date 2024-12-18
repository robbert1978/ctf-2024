console.log("[!] SECURING MISSION CRITICAL HEAP MENU [!]");
console.log("[!] NO HACKING ALLOWED	  	        [!]");

var set_username = null;
var print_username = null;
var sizes = null;
var chunks = null;
var nr_chunks = null;
var do_malloc = null;
var do_free = null;

var rm = Process.getModuleByName("epfl_heap");
var syms = rm.enumerateSymbols();
for(let i in syms){
  let n = syms[i].name;
  let a = syms[i].address;
  if(n === "nr_chunks"){
    nr_chunks = a.readPointer();
  }
  if(n === "sizes"){
    sizes = a;
  }
  if(n === "chunks"){
    chunks = a;
  }
  if(n === "do_free"){
    do_free = a;
  }
  if(n === "do_malloc"){
    do_malloc = a;
  }
  if(n === "set_username"){
    set_username = a;
  }
  if(n === "print_username"){
    print_username = a;
  }
}

if(do_malloc === null || 
  do_free === null || 
  sizes === null ||
  nr_chunks === null ||
  sizes === null ||
  set_username === null ||
  print_username === null
  )
{
  console.log("[!] failed to grab symbols... [!]");
  while(1){}
}

var _read = new NativeFunction(Module.findExportByName(null, "read"), 'int', ['int', 'pointer', 'int']);

var chünks = {};
var user_u8v;
var user_bm;
var user_ab;
var user_setup = 0;

function _do_user_set(a){
  if(!user_setup){
    user_bm = Memory.alloc(0x100);
    user_ab = ArrayBuffer.wrap(user_bm, 0x100);
    user_u8v = new Uint8Array(user_ab);
  }
  user_setup=1;
  console.log("your username?");
  _read(0, user_ab.unwrap(), 0x100);
}

function _do_user_print(a){
  if(!user_setup){
    return; 
  }
  let username_text = String.fromCharCode.apply(null, new Uint8Array(user_ab));
  console.log("current user: " + username_text);
}

function _do_mälloc(a){
  var b = Memory.alloc(a);
  chünks[a] = b;
  return b;
}

function _do_free(b){
  for(let a in chünks) {
    let c = chünks[a];
    if(c.equals(b)){
      delete chünks[a];
      break;
    }
  } 
  // prevent UAF
  let chunk_ptr = chunks;
  let sizes_ptr = sizes;
  for(let i=0; i<nr_chunks; i++){
    let p = chunk_ptr.readPointer();
    let zero = new NativePointer(0x0);
    if(p.equals(b)){
      chunk_ptr.writePointer(zero);
      break;
    }
    chunk_ptr = chunk_ptr.add(8);
  }
}

var _user_set = new NativeCallback(_do_user_set, 'void', ['pointer']);
var _user_print = new NativeCallback(_do_user_print, 'void', ['pointer']);
var _mälloc = new NativeCallback(_do_mälloc, 'pointer', ['int']);
var _free = new NativeCallback(_do_free, 'void', ['pointer']);

Interceptor.replace(do_malloc, _mälloc);
Interceptor.replace(do_free, _free);
Interceptor.replace(set_username, _user_set);
Interceptor.replace(print_username, _user_print);
