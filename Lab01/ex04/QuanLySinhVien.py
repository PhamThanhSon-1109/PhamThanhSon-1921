from SinhVien import SinhVien

class QuanLySinhVien:
    def __init__(self):
        self.listSinhVien = []
    
    def generateID(self):
        maxID = 1
        if (self.soLuongSinhVien() > 0):
            maxID = self.listSinhVien[0]._id
            for sv in self.listSinhVien:
                if (maxID < sv._id):
                    maxID = sv._id
            maxID = maxID + 1
        return maxID
    
    def soLuongSinhVien(self):
        return self.listSinhVien.__len__()
    
    def nhapSinhVien(self):
        svId = self.generateID()
        name = input("Nhap ten sinh vien: ")
        sex = input("Nhap gioi tinh sinh vien: ")
        major = input("Nhap chuyen nganh cua sinh vien: ")
        diemTB = float(input("Nhap diem cua sinh vien: "))
        
        sv = SinhVien(svId, name, sex, major, diemTB)
        self.xepLoaiHocLuc(sv)
        self.listSinhVien.append(sv)
    
    def updateSinhVien(self, ID):
        sv = self.findByID(ID)
        if (sv != None):
            name = input("Nhap ten sinh vien: ")
            sex = input("Nhap gioi tinh sinh vien: ")
            major = input("Nhap chuyen nganh cua sinh vien: ")
            diemTB = float(input("Nhap diem cua sinh vien: "))
            
            sv._name = name
            sv._sex = sex
            sv._major = major
            sv._diemTB = diemTB
            self.xepLoaiHocLuc(sv)
        else:
             print("Sinh vien co ID = {} khong ton tai.".format(ID))
    
    def sortByID(self):
        self.listSinhVien.sort(key=lambda x: x._id, reverse=False)
    
    def sortByName(self):
        self.listSinhVien.sort(key=lambda x: x._name, reverse=False)
    
    def sortByDiemTB(self):
        self.listSinhVien.sort(key=lambda x: x._diemTB, reverse=False)
    
    def findByID(self, ID):
        searchResult = None
        if(self.soLuongSinhVien() > 0):
            for sv in self.listSinhVien:
                if sv._id == ID:
                    searchResult = sv
        return searchResult
    
    def findByName(self, keyword):
        listSV = []
        if (self.soLuongSinhVien() > 0):
            for sv in self.listSinhVien:
                if (keyword.upper() in sv._name.upper()):
                    listSV.append(sv)
        return listSV
    
    def deleteByID(self, ID):
        isDeleted = False
        sv = self.findByID(ID)
        if (sv != None):
            self.listSinhVien.remove(sv)
            isDeleted = True   
    
    def xepLoaiHocLuc(self, sv:SinhVien):
        if (sv._diemTB >= 8):
            sv._hocLuc = "Gioi"
        elif (sv._diemTB >= 6.5):
            sv._hocLuc = "Kha"
        elif (sv._diemTB >= 5):
            sv._hocLuc = "Trung binh"
        else:
            sv._hocLuc = "Yeu"
    
    def showSinhVien(self, listSV):
        print("{:<8} {:<8} {:<8} {:<8} {:<8} {:<8}".format("ID", "Ten", "Gioi tinh", "Chuyen nganh", "Diem TB", "Hoc luc"))
        if(listSV.__len__() > 0):
            for sv in listSV:
                print("{:<8} {:<8} {:<8} {:<8} {:<8} {:<8}".format(sv._id, sv._name, sv._sex, sv._major, sv._diemTB, sv._hocLuc))
        print("\n")
    
    def getListSinhVien(self):
        return self.listSinhVien

         
      
    