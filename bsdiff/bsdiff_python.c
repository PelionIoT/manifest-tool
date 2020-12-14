// ----------------------------------------------------------------------------
// Copyright 2019-2020 Pelion
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
// ----------------------------------------------------------------------------

#include <Python.h>

#include "common.h"
#include "bsdiff.h"
#include "bsdiff_helper.h"

#define MODULE_NAME "armbsdiff"

void deliver_error(const char *msg){
    PyErr_SetString(PyExc_RuntimeError, msg);
}

static PyObject *armbsdiff_get_version(PyObject *self, PyObject *args) {
   const char *version = bsdiff_get_version();

   return Py_BuildValue("s", version);
}


static PyObject *armbsdiff_generate(PyObject *self, PyObject *args) {
    const char* old_fw_img = NULL;
    const char* new_fw_img = NULL;
    const char* delta_file = NULL;
    int64_t max_frame_size = 0;

    if (!PyArg_ParseTuple(args, "sssL", &old_fw_img, &new_fw_img, &delta_file, &max_frame_size)) {
        return NULL;
    }

    int status = do_diff(old_fw_img, new_fw_img, delta_file, max_frame_size);
    if (0 != status) {
        return NULL;  // flag an error
    }
    Py_RETURN_NONE;
}


// Method definition object for this extension
static PyMethodDef armbsdiff_methods[] = {
    { "get_version", (PyCFunction)armbsdiff_get_version, METH_NOARGS, "Get bsdiff version" },
    { "generate", (PyCFunction)armbsdiff_generate, METH_VARARGS, "Generate delta patch" },
    { NULL, NULL, 0, NULL }
};

#if PY_MAJOR_VERSION >= 3

static struct PyModuleDef moduledef = {
        PyModuleDef_HEAD_INIT,
        MODULE_NAME,
        NULL,
        0,
        armbsdiff_methods,
};

PyMODINIT_FUNC PyInit_armbsdiff(void)
{
    PyObject *module = PyModule_Create(&moduledef);
    return module;
}



#else

PyMODINIT_FUNC initarmbsdiff(void)
{
    Py_InitModule(MODULE_NAME, armbsdiff_methods);
    return;
}

#endif  //PY_MAJOR_VERSION >= 3

