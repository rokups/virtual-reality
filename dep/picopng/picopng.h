#pragma once


#include <stl/stddef.h>
#include <stl/vector.h>

int decodePNG(stl::vector<unsigned char>& out_image, unsigned long& image_width, unsigned long& image_height,
    const unsigned char* in_png, size_t in_size, bool convert_to_rgba32 = true);
