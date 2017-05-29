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

	void Method(const FunctionCallbackInfo<Value>& args) {
		Isolate* isolate = args.GetIsolate();

		String::Utf8Value v8_mode(args[0]->ToString());
		String::Utf8Value v8_key(args[1]->ToString());
		String::Utf8Value v8_plain(args[2]->ToString());
		char* mode = *v8_mode;
		char* key = *v8_key;
		char* plain = *v8_plain;

		init_key(char2bit(key));

		if(!strcmp(mode, "-en")) {
			encrypt_num(plain);
		} else if (!strcmp(mode, "-dn")) {
			decrypt_num(plain);
		}

		//args.GetReturnValue().Set(String::NewFromUtf9(isolate, plain));

		/*
		Handle<v8::Object > v8Obj = v8::Object::New();
		v8Obj->Set(String::NewFromUtf8(isolate, "key"), 1);
		args.GetReturnValue().Set(v8Obj);
		 */

		Local<Object> v8_storage = Object::New(isolate);
		Local<Array> v8_storage_keys = Array::New(isolate);
		Local<Array> v8_storage_states = Array::New(isolate);
		for (int i = 0; i < 16; i++) {
			v8_storage_keys->Set(i, String::NewFromUtf8(isolate, sto.keys[i]));
		}
		for (int i = 0; i < 20; i++) {
			v8_storage_states->Set(i, String::NewFromUtf8(isolate, sto.states[i]));
		}
		v8_storage->Set(String::NewFromUtf8(isolate, "keys"), v8_storage_keys);
		v8_storage->Set(String::NewFromUtf8(isolate, "states"), v8_storage_states);
		v8_storage->Set(String::NewFromUtf8(isolate, "cipher_text"), String::NewFromUtf8(isolate, plain));

		args.GetReturnValue().Set(v8_storage);
	}

	void init(Local<Object> exports) {
		NODE_SET_METHOD(exports, "DES_data", Method);
		NODE_SET_METHOD(exports, "F_computing", F_computing);
		NODE_SET_METHOD(exports, "XOR_computing", XOR_computing);
		NODE_SET_METHOD(exports, "E_computing", E_computing);
		NODE_SET_METHOD(exports, "SBOX_computing", SBOX_computing);
		NODE_SET_METHOD(exports, "file_operation", file_operation);
	}

	NODE_MODULE(addon, init)
}
