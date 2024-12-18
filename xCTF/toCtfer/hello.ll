
declare i32 @write(i32, i8*, i32)
declare i32 @printf(i8*, ...)

define i32 @ugo_main_main() {
	%t0 = add i32 0, 0
	ret i32 %t0
}
define i32 @ugo_main_init() {
	ret i32 0
}

define i32 @main() {
	call i32() @ugo_main_init()
	call i32() @ugo_main_main()
	ret i32 0
}
