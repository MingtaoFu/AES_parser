#include <node.h>
#include <cstring>
extern "C" {
#include "main.h"
}

namespace demo {

	using v8::FunctionCallbackInfo;
	using v8::Isolate;
	using v8::Local;
	using v8::Object;
	using v8::String;
	using v8::Value;
	using v8::Array;
	using v8::Function;
	/*

	void F_computing(const FunctionCallbackInfo<Value>& args) {
		Isolate* isolate = args.GetIsolate();

		String::Utf8Value v8_R(args[0]->ToString());
		String::Utf8Value v8_key(args[1]->ToString());
        char* R = *v8_R;
		char* key = *v8_key;

		f_computing(R, key);

		args.GetReturnValue().Set(String::NewFromUtf8(isolate, R));
	}

	void XOR_computing(const FunctionCallbackInfo<Value>& args) {
		Isolate* isolate = args.GetIsolate();

		String::Utf8Value v8_a(args[0]->ToString());
		String::Utf8Value v8_b(args[1]->ToString());
        char* a = *v8_a;
		char* b = *v8_b;

		xor_computing(a, b);

		args.GetReturnValue().Set(String::NewFromUtf8(isolate, a));
	}

	void E_computing(const FunctionCallbackInfo<Value>& args) {
		Isolate* isolate = args.GetIsolate();

		String::Utf8Value v8_a(args[0]->ToString());
        char* a = *v8_a;
		char output[13]; //12 + \0

        e_computing(a, output);

		args.GetReturnValue().Set(String::NewFromUtf8(isolate, output));
	}

	void SBOX_computing(const FunctionCallbackInfo<Value>& args) {
		Isolate* isolate = args.GetIsolate();

		String::Utf8Value v8_a(args[0]->ToString());
        char* a = *v8_a;
		char output[9]; //8 + \0

        sbox_computing(a, output);

		args.GetReturnValue().Set(String::NewFromUtf8(isolate, output));
	}

	void file_operation(const FunctionCallbackInfo<Value>& args) {
		printf("1\n");
		Isolate* isolate = args.GetIsolate();

		String::Utf8Value v8_mode(args[0]->ToString());
		String::Utf8Value v8_key(args[1]->ToString());
		String::Utf8Value v8_in_path(args[2]->ToString());
		String::Utf8Value v8_out_path(args[3]->ToString());
		Local<Function> cb = Local<Function>::Cast(args[4]);
		char* mode = *v8_mode;
		char* key = *v8_key;
		char* in = *v8_in_path;
		char* out = *v8_out_path;

		init_key(char2bit(key));

		if(!strcmp(mode, "-ef")) {
			encrypt_file(in, out);
			const unsigned argc = 1;
			Local<Value> argv[argc] = { String::NewFromUtf8(isolate, in) };
			cb->Call(Null(isolate), argc, argv);
		} else if (!strcmp(mode, "-df")) {
			//decrypt_file(in, out);
		}
	}
	*/

    void char2num(char* input, char* output) {
        int i = 0;
        unsigned char ch, ch2;
        while ((ch = input[i]) != '\0') {
            ch2 = input[i+1];
            if (ch >= 48 && ch <= 57) {
                // 数字
                ch = (unsigned char)(ch - 48);
            } else if (ch >= 97 && ch <= 102) {
                // 小写字母
                ch = (unsigned char)(ch - 87);
            } else if (ch >= 65 && ch <= 70) {
                // 大写字母
                ch = (unsigned char)(ch - 55);
            } else {
                printf("输入有错误\n");
                return;
            }

            if (ch2 >= 48 && ch2 <= 57) {
                // 数字
                ch2 = (unsigned char)(ch2 - 48);
            } else if (ch2 >= 97 && ch2 <= 102) {
                // 小写字母
                ch2 = (unsigned char)(ch2 - 87);
            } else if (ch2 >= 65 && ch2 <= 70) {
                // 大写字母
                ch2 = (unsigned char)(ch2 - 55);
            } else {
                printf("输入有错误\n");
                return;
            }

            output[i / 2] = ch;
            output[i / 2] <<= 4;
            output[i / 2] |= ch2;
            i+=2;
        }
    }

    void Method(const FunctionCallbackInfo<Value>& args) {
		Isolate* isolate = args.GetIsolate();

		String::Utf8Value v8_mode(args[0]->ToString());
		String::Utf8Value v8_key(args[1]->ToString());
		String::Utf8Value v8_plain(args[2]->ToString());
		char* mode = *v8_mode;
		char* key = *v8_key;
		char* plain = *v8_plain;

        char key_num[17];
        char plain_num[17];
        char2num(key, key_num);
        char2num(plain, plain_num);

		//init_key(char2bit(key));
		AES_KEY aes_key;


        unsigned char out[150];
		if(!strcmp(mode, "-en")) {
            AES_set_encrypt_key2(reinterpret_cast<const unsigned char*>(key_num), NULL, &aes_key);
			AES_encrypt_data2(reinterpret_cast<const unsigned char*>(plain_num), out, &aes_key);
		} else if (!strcmp(mode, "-dn")) {
            printf("sadsadsadsadsa\n");
            AES_set_decrypt_key2_test(reinterpret_cast<const unsigned char*>(key_num), NULL, &aes_key);
            AES_decrypt_data2(reinterpret_cast<const unsigned char*>(plain_num), out, &aes_key);
		} else {
            return;
        }

		Local<Object> v8_storage = Object::New(isolate);
		Local<Array> v8_storage_words = Array::New(isolate);
		Local<Array> v8_storage_states = Array::New(isolate);
		for (int i = 0; i < 44; i++) {
			uint32_t word = aes_key.rd_key[i];
			char w[13];
			for (int j = 0; j < 4; j++) {
				sprintf(&w[j*3], "%02x ",  (word >> (j * 8) & 0xff));
				//printf("%02x ",  (word >> ((3 - j) * 8)) & 0xff);
			}
			v8_storage_words->Set(i, String::NewFromUtf8(isolate, w));
		}
		for (int i = 0; i < 42; i++) {
			v8_storage_states->Set(i, String::NewFromUtf8(isolate, sto.states[i]));
		}
		v8_storage->Set(String::NewFromUtf8(isolate, "words"), v8_storage_words);
		v8_storage->Set(String::NewFromUtf8(isolate, "states"), v8_storage_states);
		v8_storage->Set(String::NewFromUtf8(isolate, "cipher_text"), String::NewFromUtf8(isolate, plain));

		args.GetReturnValue().Set(v8_storage);
	}

	void init(Local<Object> exports) {
		NODE_SET_METHOD(exports, "AES_data", Method);
        /*
		NODE_SET_METHOD(exports, "F_computing", F_computing);
		NODE_SET_METHOD(exports, "XOR_computing", XOR_computing);
		NODE_SET_METHOD(exports, "E_computing", E_computing);
		NODE_SET_METHOD(exports, "SBOX_computing", SBOX_computing);
		NODE_SET_METHOD(exports, "file_operation", file_operation);
         */
	}

	NODE_MODULE(addon, init)
}
