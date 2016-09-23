from libc cimport stdio

cdef extern from "jansson.h":
    ctypedef struct json_t:
        pass

    ctypedef struct json_error_t:
        pass

    void json_decref(json_t *json)
    json_t *json_loads(const char *input, size_t flags, json_error_t *error)
    char *json_dumps(const json_t *json, size_t flags)

    # misc
    void json_object_seed(size_t seed)
