from PIL import Image
from utils import *


def encode(initial_text):
    img = Image.open('input.png')
    pixels = img.load()

    text_bits = tobits(initial_text)

    length_bits = alignedbin32(len(text_bits))
    all_bits = length_bits + text_bits

    pixelcount = 0

    for i in range(img.size[0]):
        for j in range(img.size[1]):
            if pixelcount >= len(all_bits):
                break

            r, g, b = pixels[i, j]

            val = all_bits[pixelcount : pixelcount + MAXCHANGE * 3]

            pixels[i, j] = insert_into_pixel(r, g, b, val)
                
            pixelcount += MAXCHANGE * 3

    newimg = Image.new(img.mode, img.size)
    newpixels = newimg.load()

    for i in range(newimg.size[0]):
        for j in range(newimg.size[1]):
            newpixels[i, j] = pixels[i, j]

    newimg.save('output.png')


def decode():
    img = Image.open('output.png')
    pixels = img.load()

    hidden_bits = ""
    hidden_bits_length = 10 ** 8
    hidden_bits_length_initialized = False

    for i in range(img.size[0]):
        for j in range(img.size[1]):
            if (not hidden_bits_length_initialized 
                and len(hidden_bits) > MAXLENGTH):
                    hidden_bits_length = get_length(hidden_bits)
                    hidden_bits = hidden_bits[MAXLENGTH:]
                    hidden_bits_length_initialized = True

            if len(hidden_bits) > hidden_bits_length:
                break

            r, g, b = pixels[i, j]
            hidden_bits += get_from_pixel(r, g, b)

    hidden_bits = hidden_bits[:hidden_bits_length]
    hidden_text = frombits(hidden_bits)

    return hidden_text


if __name__ == "__main__":
    initial_text = """
        Lorem ipsum dolor sit amet, consectetur adipiscing elit. 
        In a augue fringilla, semper erat eget, accumsan diam. 
        Vivamus placerat ut arcu et vulputate. 
        Vestibulum auctor nisi pellentesque, elementum lorem non, molestie magna.
    """
    
    encode(initial_text)
    hidden_text = decode()

    print(f"initial_text = {initial_text}")
    print(f"hidden_text = {hidden_text}")
    print(f"texts_equals = {initial_text == hidden_text}")