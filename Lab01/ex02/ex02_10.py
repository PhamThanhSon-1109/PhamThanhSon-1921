def dao_nguoc(chuoi):
    return chuoi[::-1]
input_string = input("moi nhap chuoi can dao nguoc: ")
print("chuoi dao nguoc la : ", dao_nguoc(input_string))