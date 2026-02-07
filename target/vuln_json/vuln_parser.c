#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_KEY_LEN 64
#define MAX_VAL_LEN 256

// Vulnerability 1: Fixed-size buffer for parsing
typedef struct {
    char key[MAX_KEY_LEN];
    char value[MAX_VAL_LEN];
} KeyValue;

// Vulnerability 2: No bounds checking on array index
void parse_array(const char* json) {
    char buffer[128];
    int index = 0;
    const char* ptr = json;
    
    while (*ptr) {
        if (*ptr >= '0' && *ptr <= '9') {
            // BUG: No bounds check on buffer
            buffer[index++] = *ptr;
        }
        ptr++;
    }
    buffer[index] = '\0';
}

// Vulnerability 3: Heap overflow in string copy
char* extract_string(const char* json, const char* key) {
    char* result = malloc(64);  // Fixed 64 bytes
    const char* start = strstr(json, key);
    
    if (!start) {
        free(result);
        return NULL;
    }
    
    start = strchr(start, ':');
    if (!start) {
        free(result);
        return NULL;
    }
    
    start = strchr(start, '"');
    if (!start) {
        free(result);
        return NULL;
    }
    start++;  // Skip opening quote
    
    const char* end = strchr(start, '"');
    if (!end) {
        free(result);
        return NULL;
    }
    
    // BUG: No length check before copy - heap overflow possible
    int len = end - start;
    memcpy(result, start, len);
    result[len] = '\0';
    
    return result;
}

// Vulnerability 4: Stack buffer overflow in key parsing
int parse_key_value(const char* json, KeyValue* kv) {
    const char* colon = strchr(json, ':');
    if (!colon) return -1;
    
    int key_len = colon - json;
    
    // BUG: No check if key_len exceeds MAX_KEY_LEN
    memcpy(kv->key, json, key_len);
    kv->key[key_len] = '\0';
    
    const char* value_start = colon + 1;
    while (*value_start == ' ' || *value_start == '"') {
        value_start++;
    }
    
    const char* value_end = value_start;
    while (*value_end && *value_end != '"' && *value_end != ',' && *value_end != '}') {
        value_end++;
    }
    
    int value_len = value_end - value_start;
    
    // BUG: No check if value_len exceeds MAX_VAL_LEN
    memcpy(kv->value, value_start, value_len);
    kv->value[value_len] = '\0';
    
    return 0;
}

// Vulnerability 5: Use-after-free potential
char* cached_data = NULL;

void process_with_cache(const char* json) {
    if (cached_data) {
        free(cached_data);
    }
    
    cached_data = extract_string(json, "data");
    
    if (!cached_data) {
        // BUG: cached_data now points to freed memory
        return;
    }
    
    printf("Cached: %s\n", cached_data);
}

int main(int argc, char** argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <json_file>\n", argv[0]);
        return 1;
    }
    
    FILE* f = fopen(argv[1], "rb");
    if (!f) {
        fprintf(stderr, "Cannot open file: %s\n", argv[1]);
        return 1;
    }
    
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    char* buffer = malloc(size + 1);
    if (!buffer) {
        fclose(f);
        return 1;
    }
    
    fread(buffer, 1, size, f);
    buffer[size] = '\0';
    fclose(f);
    
    // Try different parsing strategies - all have bugs
    if (strstr(buffer, "[")) {
        parse_array(buffer);
    }
    
    if (strstr(buffer, "data")) {
        process_with_cache(buffer);
    }
    
    KeyValue kv;
    if (strchr(buffer, ':')) {
        parse_key_value(buffer, &kv);
    }
    
    free(buffer);
    return 0;
}
