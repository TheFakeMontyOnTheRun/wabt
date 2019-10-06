/*
 * Copyright 2019 WebAssembly Community Group participants
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <wasm.h>

#include "src/binary-reader.h"
#include "src/error.h"
#include "src/error-formatter.h"
#include "src/interp/binary-reader-interp.h"
#include "src/interp/interp.h"
#include "src/ir.h"
#include "src/stream.h"

using namespace wabt;
using namespace wabt::interp;

static Features s_features;
static Stream* s_trace_stream;
static Thread::Options s_thread_options;
static std::unique_ptr<FileStream> s_log_stream;
static std::unique_ptr<FileStream> s_stdout_stream;

struct wasm_engine_t {
};

struct wasm_store_t {
  wasm_store_t(Environment* env, Executor* executor) : env(env), executor(executor) {
  }

  ~wasm_store_t() {
    delete executor;
  }

  Environment* env;
  Executor* executor;
};

struct wasm_functype_t {
  interp::FuncSignature sig;
};

struct wasm_func_t {
  const wasm_functype_t* type;
  wasm_func_callback_t callback;
};

struct wasm_extern_t {
  wasm_func_t* func;
};

struct wasm_module_t {
  wasm_module_t(const wasm_byte_vec_t* in, ModuleMetadata* metadata) : metadata(metadata) {
    wasm_byte_vec_copy(&binary, in);
  }
  ~wasm_module_t() {
    wasm_byte_vec_delete(&binary);
    delete metadata;
  }
  wasm_byte_vec_t binary;
  ModuleMetadata* metadata;
};

struct wasm_instance_t {
  wasm_instance_t(wasm_store_t* store, DefinedModule* module) : store(store), module(module) {
  }
  ~wasm_instance_t() {
    delete module;
  }
  wasm_store_t* store;
  DefinedModule* module;
};

// wasm_engine
wasm_engine_t* wasm_engine_new() {
  return new wasm_engine_t();
}

wasm_engine_t* wasm_engine_new_with_config(wasm_config_t*) {
  assert(false);
  return NULL;
}

void wasm_engine_delete(wasm_engine_t* engine) {
  assert(engine);
  delete engine;
}

// wasm_store

wasm_store_t* wasm_store_new(wasm_engine_t* engine) {
  assert(engine);
  if (!s_trace_stream) {
    s_trace_stream = s_stdout_stream.get();
  }
  Environment* env = new Environment;;
  Executor* executor = new Executor(env, s_trace_stream, s_thread_options);
  return new wasm_store_t(env, executor);
}

void wasm_store_delete(wasm_store_t* store) {
  assert(store);
  delete store;
}

// wasm_module

static ReadBinaryOptions get_options() {
  const bool kReadDebugNames = true;
  const bool kStopOnFirstError = true;
  const bool kFailOnCustomSectionError = true;
  return ReadBinaryOptions(s_features, s_log_stream.get(), kReadDebugNames,
                           kStopOnFirstError, kFailOnCustomSectionError);
}

wasm_module_t* wasm_module_new(wasm_store_t*, const wasm_byte_vec_t* binary) {
  Errors errors;
  ModuleMetadata* metadata = nullptr;
  wabt::Result result = ReadBinaryMetadata(binary->data, binary->size,
                                           get_options(), &errors, &metadata);
  if (!Succeeded(result)) {
    return NULL;
  }
  return new wasm_module_t(binary, metadata);
}

void wasm_module_delete(wasm_module_t* module) {
  assert(module);
  delete module;
}

// wasm_instance

static interp::Result Callback(const HostFunc* func,
                               const interp::FuncSignature* sig,
                               const TypedValues& args,
                               TypedValues& results) {
  printf("called host ");
  return interp::Result::Ok;
}


static void create_host_modules(Environment* env,
                                const wasm_extern_t* const imports[]
                                , ModuleMetadata* metadata) {
  for (size_t i = 0; i < metadata->imports.size(); i++) {
    const auto& import = metadata->imports[i];
    const wasm_extern_t* ext = imports[i];
    assert(ext);
    std::map<std::string, HostModule*> modules;
    if (modules.count(import.module_name) == 0) {
      modules[import.module_name] = env->AppendHostModule(import.module_name);
    }
    auto* host_module = modules[import.module_name];
    const interp::FuncSignature& sig = imports[i]->func->type->sig;
    host_module->AppendFuncExport(import.field_name, sig, Callback);

    printf("import: %s . %s\n", import.module_name.c_str(), import.field_name.c_str());
  }


  /*
  if (s_host_print) {
    host_module->on_unknown_func_export =
        [](Environment* env, HostModule* host_module, string_view name,
           Index sig_index) -> Index {
      if (name != "print") {
        return kInvalidIndex;
      }

    };
  }
  */
}

wasm_instance_t* wasm_instance_new(wasm_store_t* store,
                                   const wasm_module_t* module,
                                   const wasm_extern_t* const imports[],
                                   wasm_trap_t**) {
  assert(module);
  assert(module->metadata);
  assert(store);
  assert(store->env);

  create_host_modules(store->env, imports, module->metadata);

  Errors errors;
  interp::DefinedModule* interp_module = nullptr;
  wabt::Result result = ReadBinaryInterp(store->env, module->binary.data,
                                         module->binary.size, get_options(),
                                         &errors, &interp_module);

  FormatErrorsToFile(errors, Location::Type::Binary);
  if (!Succeeded(result)) {
    return NULL;
  }
  return new wasm_instance_t(store, interp_module);
}

void wasm_instance_delete(wasm_instance_t* instance) {
  assert(instance);
  delete instance;
}

void wasm_instance_exports(const wasm_instance_t* instance,
                           wasm_extern_vec_t* out) {
  size_t num_exports = instance->module->exports.size();
  out->size = num_exports;
  out->data = new wasm_extern_t*[out->size];

  for (size_t i = 0; i < num_exports; i++) {
    const interp::Export& exp = instance->module->exports[i];
    switch (exp.kind) {
      case ExternalKind::Func: {
        wasm_extern_t* wasm_extern = new wasm_extern_t;
        out->data[i] = wasm_extern;
        /*
        wasm_functype
        func->sig =
        */
        printf("%s\n", exp.name.c_str());
        break;
      } default:
        assert(false);
    }
  }
}

// wasm_functype
static Type to_wabt_type(wasm_valkind_t kind) {
  switch (kind) {
    case WASM_I32:
      return Type::I32;
    case WASM_I64:
      return Type::I64;
    case WASM_F32:
      return Type::F32;
    case WASM_F64:
      return Type::F64;
    case WASM_ANYREF:
      return Type::Anyref;
    case WASM_FUNCREF:
      return Type::Funcref;
  }
  assert(false);
}

wasm_functype_t* wasm_functype_new(wasm_valtype_vec_t* params, wasm_valtype_vec_t* results) {
  std::vector<Type> param_vec;
  std::vector<Type> result_vec;
  for (size_t i = 0; i < params->size; i++) {
    param_vec.push_back(to_wabt_type(wasm_valtype_kind(params->data[i])));
  }
  for (size_t i = 0; i < results->size; i++) {
    result_vec.push_back(to_wabt_type(wasm_valtype_kind(results->data[i])));
  }
  return new wasm_functype_t{interp::FuncSignature{param_vec, result_vec}};
}

void wasm_functype_delete(wasm_functype_t* functype) {
  assert(functype);
  delete(functype);
}

// wasm_func

wasm_func_t* wasm_func_new(wasm_store_t*,
                           const wasm_functype_t* type,
                           wasm_func_callback_t callback) {
  return new wasm_func_t{type, callback};
}

void wasm_func_delete(wasm_func_t* func) {
  assert(func);
  delete func;
}

wasm_trap_t* wasm_func_call(const wasm_func_t*,
                            const wasm_val_t args[],
                            wasm_val_t results[]) {
  assert(false);
  return NULL;
}

// wasm_byte_vec
void wasm_byte_vec_new_uninitialized(wasm_byte_vec_t* out, size_t size) {
  out->data = new wasm_byte_t[size];
  out->size = size;
}

void wasm_byte_vec_copy(wasm_byte_vec_t* out, const wasm_byte_vec_t* vec) {
  wasm_byte_vec_new_uninitialized(out, vec->size);
  memcpy(out->data, vec->data, vec->size);
}

void wasm_byte_vec_delete(wasm_byte_vec_t* vec) {
  assert(vec);
  delete vec->data;
  vec->size = 0;
  vec->data = NULL;
}


// wasm_valtype
struct wasm_valtype_t {
  wasm_valkind_enum kind;
};

wasm_valkind_t wasm_valtype_kind(const wasm_valtype_t* type) {
  assert(type);
  return type->kind;
}

// wasm_valtype_vec
void wasm_valtype_vec_new_empty(wasm_valtype_vec_t* out) {
  out->data = NULL;
  out->size = 0;
}

// wasm_extern_vec
void wasm_extern_vec_new(wasm_extern_vec_t* vec) {
  assert(false);
}
void wasm_extern_vec_delete(wasm_extern_vec_t* vec) {
  assert(false);
}

// Externals
wasm_extern_t* wasm_func_as_extern(wasm_func_t* func) {
  return new wasm_extern_t{func};
}

wasm_func_t* wasm_extern_as_func(wasm_extern_t* ext) {
  return ext->func;
}

