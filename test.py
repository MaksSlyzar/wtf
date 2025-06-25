from assembler import assemble_program

def normalize_580_file_inplace(file_path, max_size=65549): 
    with open(file_path, "rb") as f:
        content = b'\x3A\x0F\x00' + f.read()

    content = content[:max_size - 2]

    content = content.ljust(max_size - 2, b'\x00')
    data = ''
    with open("./wtf.txt", "r") as f:
        data = f.read()
    
    output = assemble_program(data.splitlines())

    new_header = output 
    content = new_header + content[len(new_header):]

    content += b'\xFF\xFF'

    with open("./new-program.580", "wb") as f:
        f.write(content)

    print(f"Файл '{file_path}' оновлено ({len(content)} байтів).")

# Приклад виклику
normalize_580_file_inplace("best.580")

