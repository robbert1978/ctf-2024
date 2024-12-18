<?php

class Zaj {
    const ERR_NO_NOTEPAD = "notepad not initialized";
    const ERR_NO_MEMO = "memo not initailized";
    const ERR_BAD_VAL = "bad value";
    const ERR_NO_NOTE = "no such note";
    const ERR_EXISTS = "already exists";
    const ERR_MEMORY = "memory error";

    static $notepad, $notepad_key;
    static $memo, $memo_key;
    static $session_key;

    static function main() {
        self::$session_key = random_int(0, 2**32 - 1);

        try {
            while(1) {
                self::vuln();
            }
        } catch(Exception $e) {
            printf("Error: %s!\n", $e->getMessage());
        }
    }

    static function choice() {
        self::puts("1. Open notepad");
        
        self::puts("2. Add note");
        self::puts("3. Edit note");
        self::puts("4. View note");
        self::puts("5. Delete note");

        self::puts("6. Add memo");
        self::puts("7. Edit memo");
        self::puts("8. View memo");
        self::puts("9. Delete memo");
    
        return self::read_int("> ");
    }

    static function vuln() {
        switch(self::choice()) {
            // Open notepad
            case 1:
                self::$notepad && throw new Exception(self::ERR_EXISTS);

                self::$notepad_key = self::id_to_key(self::read_int("Notepad id: "));
                if(self::$notepad_key === 0 || self::$notepad_key === self::$memo_key) {
                    throw new Exception(self::ERR_BAD_VAL);
                }

                $notepad_size = self::read_int("Size: ");
                if($notepad_size <= 0x100 || $notepad_size > 0x100000) {
                    throw new Exception(self::ERR_BAD_VAL);
                }

                self::$notepad = shm_attach(self::$notepad_key, $notepad_size);
                if(!self::$notepad) {
                    throw new Exception(self::ERR_MEMORY);
                }
                break;

            // Add/Edit note
            case 2:
            case 3:
                self::$notepad || throw new Exception(self::ERR_NO_NOTEPAD);
                
                $note_id = self::read_int("Note id: ");
                $note_contents = self::read_string("Note contents: ");

                if(!shm_put_var(self::$notepad, $note_id, $note_contents)) {
                    throw new Exception(self::ERR_MEMORY);
                }
                break;

            // View note
            case 4:
                self::$notepad || throw new Exception(self::ERR_NO_NOTEPAD);
                
                $note_id = self::read_int("Note id: ");
                if(shm_has_var(self::$notepad, $note_id)) {
                    self::puts(shm_get_var(self::$notepad, $note_id));
                } else {
                    throw new Exception(self::ERR_NO_NOTE);
                }
                break;

            // Delete note
            case 5:
                self::$notepad || throw new Exception(self::ERR_NO_NOTEPAD);
                
                $note_id = self::read_int("Note id: ");
                if(shm_has_var(self::$notepad, $note_id)) {
                    shm_remove_var(self::$notepad, $note_id);
                } else {
                    throw new Exception(self::ERR_NO_NOTE);
                }
                break;

            // Add memo
            case 6:
                self::$memo && throw new Exception(self::ERR_EXISTS);

                self::$memo_key = self::id_to_key(self::read_int("Memo id: "));
                if(self::$memo_key === 0 || self::$memo_key === self::$notepad_key) {
                    throw new Exception(self::ERR_BAD_VAL);
                }

                $memo_size = self::read_int("Size: ");
                if($memo_size <= 0 || $memo_size > 0x100) {
                    throw new Exception(self::ERR_BAD_VAL);
                }

                self::$memo = shmop_open(self::$memo_key, "c", 0666, $memo_size);
                if (!self::$memo) {
                    throw new Exception(self::ERR_MEMORY);
                }
                break;
            
            // Edit memo
            case 7:
                self::$memo || throw new Exception(self::ERR_NO_MEMO);
                $memo_contents = self::read_string("Memo contents: ");
                shmop_write(self::$memo, $memo_contents, 0);
                break;

            // View memo
            case 8:
                self::$memo || throw new Exception(self::ERR_NO_MEMO);
                self::puts(shmop_read(self::$memo, 0, 0));
                break;

            // Delete memo
            case 9:
                self::$memo || throw new Exception(self::ERR_NO_MEMO);
                shmop_delete(self::$memo);
                self::$memo = self::$memo_key = NULL;
                break;
            
            case 10:
                self::puts(phpversion());
                break;
            
            default:
                exit();
                break;
        }
    }

    static function id_to_key($id) {
        return $id ^ self::$session_key;
    }

    static function read_string($prompt) {
        print($prompt);
        return substr(fgets(STDIN), 0, -1);
    }

    static function read_int($prompt) {
        return (int) self::read_string($prompt);
    }

    static function puts($str) {
        print($str . "\n");
    }
}

Zaj::main();
