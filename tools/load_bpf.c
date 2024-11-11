#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>

int main(int argc, char** argv) {
    struct bpf_object *obj;
    const char *filename = "pkg/bpf/bytecode/restricted-mount.bpf.o";
    int err;

	if(argc == 2) filename = argv[1];
    struct rlimit rlim = {RLIM_INFINITY, RLIM_INFINITY};
    if (setrlimit(RLIMIT_MEMLOCK, &rlim)) {
        perror("Failed to set RLIMIT_MEMLOCK");
        return 1;
    }
    obj = bpf_object__open(filename);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "Error loading BPF object from file: %s\n", filename);
        return 1;
    }
    obj = bpf_object__open_file(filename, NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "Error loading BPF object from file: %s\n", filename);
        return 1;
    }
	FILE *file = fopen(filename, "rb");
    if (file == NULL) {
        perror("Failed to open BPF object file");
        return 1;
    }

    fseek(file, 0, SEEK_END);
    size_t obj_buf_sz = ftell(file);
    fseek(file, 0, SEEK_SET);

    void *obj_buf = malloc(obj_buf_sz);
    if (obj_buf == NULL) {
        perror("Failed to allocate memory for BPF object buffer");
        fclose(file);
        return 1;
    }

    if (fread(obj_buf, 1, obj_buf_sz, file) != obj_buf_sz) {
        perror("Failed to read BPF object file");
        free(obj_buf);
        fclose(file);
        return 1;
    }

    fclose(file);
	obj = bpf_object__open_mem(obj_buf, obj_buf_sz, NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "Error loading BPF object from memory\n");
        free(obj_buf);
        return 1;
    }

    printf("BPF object name %s\n", bpf_object__name(obj));
	struct bpf_program *p = NULL;
	for(;;){
		p = bpf_object__next_program(obj, p);
		if (p == NULL) break;
		printf("BPF %s prog, %s, type %d, %d\n", bpf_program__name(p), bpf_program__section_name(p), 
		bpf_program__type(p), bpf_program__expected_attach_type(p));
	}

    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "Error loading BPF object: %d\n", err);
        bpf_object__close(obj);
        return 1;
    }

    printf("BPF object loaded successfully\n");

    bpf_object__close(obj);
    return 0;
    
}
