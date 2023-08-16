#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <winnt.h>

//函数声明
//**************************************************************************
//ReadPEFile:将文件读取到缓冲区
//参数说明：
//lpszFile 文件路径
//pFileBuffer 缓冲区指针
//返回值说明：
//读取失败返回0  否则返回实际读取的大小
//**************************************************************************
DWORD ReadPEFile(IN LPSTR lpszFile,OUT LPVOID* pFileBuffer){
    //文件指针
    FILE* pfile = NULL;
    
    //打开文件，并将返回的FILE* 给创建的文件指针
    //判断pfile是否不为NULL
    if(!(pfile = fopen(lpszFile,"rb"))){
        printf("Can`t open the file!\n");
        exit(1);
    }

    //传入一个FILE* 指针 设置偏移为0 且指向文件末尾
    fseek(pfile,0,SEEK_END);

    //文件大小
    DWORD fileSize;
    //返回给定流的当前文件位置
    fileSize = ftell(pfile);
    // printf("This file is %d bytes!\n",fileSize); 

    //将文件指针设置到文件开头
    fseek(pfile,0,SEEK_SET);

    if(!(*pFileBuffer = malloc(fileSize))){
        printf("Can`t malloc filebuffer!\n");
        fclose(pfile);
        return 0;
    }
    printf("FileBuffer need malloc %d bytes\n",fileSize);

    //写入大小
    DWORD wriSize;
    wriSize = fread(*pFileBuffer,1,fileSize,pfile);
    if (!wriSize){
        printf("Can`t copy file to buff!\n");
        fclose(pfile);
        return 0;
    }

    //关闭文件
    fclose(pfile);
    //返回写入Buff的大小
    return wriSize;

}

//**************************************************************************
//CopyFileBufferToImageBuffer:将文件从FileBuffer复制到ImageBuffer
//参数说明：
//pFileBuffer  FileBuffer指针
//pImageBuffer ImageBuffer指针
//返回值说明：
//读取失败返回0  否则返回复制的大小
//**************************************************************************
DWORD CopyFileBufferToImageBuffer(IN LPVOID pFileBuffer,OUT LPVOID* pImageBuffer){
    PIMAGE_DOS_HEADER pDh = NULL;
    PIMAGE_NT_HEADERS pN32h = NULL;
    PIMAGE_FILE_HEADER pFh = NULL;
    PIMAGE_OPTIONAL_HEADER pO32h = NULL;
    PIMAGE_SECTION_HEADER pSh = NULL;

    //将FileBuffer指向DOS头 
    pDh = (PIMAGE_DOS_HEADER)pFileBuffer;
    if(pDh->e_magic != IMAGE_DOS_SIGNATURE){
        printf("Not a valid PE file! Error by Dos header!\n");
        return 0;
    }

    //DOS头加上DOS头偏移找到NT头
    pN32h = (PIMAGE_NT_HEADERS)((DWORD64)pDh + pDh->e_lfanew);
    //判断软件的IMAGE_NT_SIGNATURE
    if (pN32h->Signature != IMAGE_NT_SIGNATURE){
        printf("Not a valid PE file! Error by NT header!\n");
        return 0;
    }

    //指向PE头
    pFh = (PIMAGE_FILE_HEADER)&(pN32h->FileHeader);
    printf("Size of OptionalHeader: %d\n",pFh->SizeOfOptionalHeader);
    printf("Size of sections: %d\n",pFh->NumberOfSections);
    //判断软件是64位还是32位
    // if (pFh->Machine == IMAGE_FILE_MACHINE_AMD64){
    //     pO64h = (PIMAGE_OPTIONAL_HEADER64)&(pN32h->OptionalHeader);
    //     DWORD Size_Image;
    //     Size_Image = pO64h->SizeOfImage;
    //     printf("SizeOfImage: %d",Size_Image);
    //     DWORD Size_Header;
    //     Size_Header = pO64h ->SizeOfHeaders;
    //     printf("SizeOfImage: %d",Size_Header);

    // }else if(pFh->Machine == IMAGE_FILE_MACHINE_I386){
    //     pO32h = (PIMAGE_OPTIONAL_HEADER)&(pN32h->OptionalHeader);
    //     DWORD Size_Image;
    //     Size_Image = pO32h->SizeOfImage;
    //     printf("SizeOfImage: %d",Size_Image);
    //     DWORD Size_Header;
    //     Size_Header = pO32h ->SizeOfHeaders;
    //     printf("SizeOfImage: %d",Size_Header);
    // }

    //指向另一个结构体-可选PE头
    pO32h = (PIMAGE_OPTIONAL_HEADER)&(pN32h->OptionalHeader);
    DWORD Size_Image;
    Size_Image = pO32h->SizeOfImage;
    printf("SizeOfImage: %d\n",Size_Image);
    DWORD Size_Header;
    Size_Header = pO32h ->SizeOfHeaders;
    printf("SizeOfHeaders: %d\n",Size_Header);

    if(!(*pImageBuffer = malloc(Size_Image * sizeof(char)))){
        printf("Can`t malloc ImageBuffer!\n");
        return 0;
    }

    //统计复制到pImageBuffer的大小
    DWORD Size_memcpy_Count = 0;
    memset(*pImageBuffer,0,Size_Image);
    memcpy(*pImageBuffer,pFileBuffer,Size_Header);
    Size_memcpy_Count += Size_Header;


    //循环读取pFileImage中已加载的节表的数据 并加载到pImageBuffer中
    //节表固定40(0x28)字节 节的数量为pFh->NumberOfSections
    for (int i = 0,j = 0; i < pFh->NumberOfSections; i++){
        //获取第i个节表在pFileImage中的位置
        pSh = (PIMAGE_SECTION_HEADER)((DWORD64)&(pN32h->OptionalHeader) + pFh->SizeOfOptionalHeader +j);
        printf("%d section of VirtualAddrs: 0x%x\n",i,pSh->VirtualAddress);
        printf("%d section of PointerToRawData: 0x%x\n",i,pSh->PointerToRawData);
        //memcpy需要两个void*类型的参数 使用LPVOID强制转换
        //Dst地址是将已申请的*pImageBuffer地址强转为DWORD64类型 *pImageBuffer为已申请的内存地址
        //再加上pSh->VirtualAddress 即为应在内存中的地址
        //VirtualAddress是该节在内存中的偏移
        //Src地址是将已加载到内存中的pFileBuffer的地址强转为DWORD64类型 并加上pSh->PointerToRawDate
        //PointerToRawDate是该节在文件中的偏移 即为该节在文件中的初始位置
        //需要复制的大小为pSh->SizeOfRawData 即为节在文件中对齐之后的尺寸
        memcpy((LPVOID)((DWORD64)(*pImageBuffer)+pSh->VirtualAddress),(LPVOID)((DWORD64)pFileBuffer+pSh->PointerToRawData),pSh->SizeOfRawData);
        Size_memcpy_Count += pSh->SizeOfRawData;
        j+=sizeof(IMAGE_SECTION_HEADER);
    }
    return Size_memcpy_Count;
}

//**************************************************************************
//CopyImageBufferToNewBuffer:将ImageBuffer中的数据复制到新的缓冲区
//参数说明：
//pImageBuffer ImageBuffer指针
//pNewBuffer NewBuffer指针
//返回值说明：
//读取失败返回0  否则返回复制的大小
//**************************************************************************
DWORD CopyImageBufferToNewBuffer(IN LPVOID pImageBuffer,OUT LPVOID* pNewBuffer){
    PIMAGE_DOS_HEADER pDh = NULL;
    PIMAGE_NT_HEADERS pN32h = NULL;
    PIMAGE_FILE_HEADER pFh = NULL;
    PIMAGE_OPTIONAL_HEADER pO32h = NULL;
    PIMAGE_SECTION_HEADER pSh = NULL;
    PIMAGE_SECTION_HEADER pSh_last = NULL;

    pDh = (PIMAGE_DOS_HEADER)pImageBuffer;
    pN32h = (PIMAGE_NT_HEADERS)((DWORD64)pDh + pDh->e_lfanew);
    pFh = (PIMAGE_FILE_HEADER)&(pN32h->FileHeader);
    pO32h = (PIMAGE_OPTIONAL_HEADER)&(pN32h->OptionalHeader);
    //*************************************************************
    //通过最后一个节的PointerToRawData(文件中偏移)+SizeOfRawData(对齐后在文件中的大小)
    //计算出NewBuffer所需要的大小
    pSh = (PIMAGE_SECTION_HEADER)((DWORD64)&(pN32h->OptionalHeader) + pFh->SizeOfOptionalHeader);
    //计算最后一个节的地址
    pSh_last = pSh + (pFh->NumberOfSections-1);
    DWORD NewBuff_Size = pSh_last->PointerToRawData + pSh_last->SizeOfRawData;
    printf("NewBuffer Need: %d bytes\n",NewBuff_Size);
    //*************************************************************

    if(!(*pNewBuffer = malloc(NewBuff_Size * sizeof(char)))){
        printf("Can`t malloc NewBuffer!\n");
        return 0;
    }
    memset(*pNewBuffer,0,NewBuff_Size);
    
    //计算SizeOfHeaders 确定需要拷贝多少字节到NewBuffer
    DWORD Size_Header;
    Size_Header = pO32h ->SizeOfHeaders;
    printf("Size of Header: %d\n",Size_Header);
    //复制全部头和节表到NewBuffer
    memcpy(*pNewBuffer, pImageBuffer, Size_Header);
    //统计复制的文件大小
    DWORD Copy_Count = 0;
    Copy_Count += Size_Header;
    printf("Size_memcpy_Count: %d\n",Copy_Count);

    //循环复制节的数据到 Newbuffer
    for (size_t i = 0; i < pFh->NumberOfSections; i++){
        DWORD Size_Sections = pSh->SizeOfRawData;
        printf("%d Section of SizeOfRawData: %x\n",i,Size_Sections);
        memcpy((LPVOID)((DWORD64)*pNewBuffer + (pSh->PointerToRawData)), (LPVOID)((DWORD64)pImageBuffer + pSh->VirtualAddress), Size_Sections);
        Copy_Count += Size_Sections;
        printf("Copy_Count: %X\n",Copy_Count);
        pSh ++;
        
    }
    
    return Copy_Count;
}

//**************************************************************************
//MemeryTOFile:将内存中的数据复制到文件
//参数说明：
//pMemBuffer 内存中数据的指针
//size 要复制的大小
//lpszFile 要存储的文件路径
//返回值说明：
//读取失败返回0  否则返回复制的大小
//**************************************************************************
BOOL MemeryTOFile(IN LPVOID pMemBuffer,IN size_t Nsize,OUT LPSTR lpszFile){
    FILE* fp = NULL;
    if(!(fp = fopen(lpszFile,"wb"))){
        printf("Can`t open the File!\n");
        return 0;
    }

    DWORD Copy_Size;
    Copy_Size = fwrite(pMemBuffer,1,Nsize,fp);
    if(!Copy_Size){
        printf("Can`t Write the File!\n");
        fclose(fp);
        return 0;
    }
    fclose(fp);
    return Copy_Size;

}


//**************************************************************************
//RvaToFileOffset:将内存偏移转换为文件偏移
//参数说明：
//pFileBuffer FileBuffer指针
//dwRva RVA的值
//返回值说明：
//返回转换后的FOA的值  如果失败返回0
//**************************************************************************
DWORD RvaToFileOffset(IN LPVOID pFileBuffer,IN DWORD dwRva){
    PIMAGE_DOS_HEADER pDh = NULL;
    PIMAGE_NT_HEADERS pN32h = NULL;
    PIMAGE_FILE_HEADER pFh = NULL;
    PIMAGE_OPTIONAL_HEADER pO32h = NULL;
    PIMAGE_SECTION_HEADER pSh = NULL;
    PIMAGE_SECTION_HEADER pSh_last = NULL;

    pDh = (PIMAGE_DOS_HEADER)pFileBuffer;
    pN32h = (PIMAGE_NT_HEADERS)((DWORD64)pDh + pDh->e_lfanew);
    pFh = (PIMAGE_FILE_HEADER)&(pN32h->FileHeader);
    pO32h = (PIMAGE_OPTIONAL_HEADER)&(pN32h->OptionalHeader);
    pSh = (PIMAGE_SECTION_HEADER)((DWORD64)&(pN32h->OptionalHeader) + pFh->SizeOfOptionalHeader);
    
    DWORD NumOfSections = pFh->NumberOfSections;

    //PointerToRawData(文件中偏移) VirtualAddress(内存中偏移)
    //如果两者相等的话 说明对其方式是一样的 直接返回
    if(pSh->PointerToRawData == pSh->VirtualAddress){
        printf("PointerToRawData == VirtualAddress");
        return dwRva;
    }

    DWORD FOA = 0;
    for (size_t i = 0; i < NumOfSections ; i++){
        if ((dwRva > pSh->VirtualAddress) && (dwRva <(pSh->VirtualAddress + pSh->Misc.VirtualSize))){
            FOA = pSh->PointerToRawData + (dwRva - pSh->VirtualAddress);
            break;
        }
        pSh ++;
        printf("RAV to FOA is in %d Section\n",i+1);
    }
    return FOA;
}

BOOL AddShellCode(){

    // SHellCode代码 执行一个弹窗
    BYTE ShellCode[] = {
    0x6a,0x00,0x6a,0x00,0x6a,0x00,0x6a,0x00,//8
    0xe8,0x00,0x00,0x00,0x00,//13
    0xe9,0x00,0x00,0x00,0x00,
    };

    //  BYTE ShellCode[] = {
    // 0xC7,0x44,0x24,0x0C,00,00,00,00,//8
    // 0xC7,0x44,0x24,0x08,00,00,00,00,//16
    // 0xC7,0x44,0x24,0x04,00,00,00,00,//24
    // 0xC7,0x44,0x24,00,00,00,00,00,//32
    // 0xe8,0x01,0x02,0x03,0x04,//37
    // 0xe9,0x05,0x06,0x07,0x08
    // };

    BYTE E8Bit = 0x9;    //修正E8指令的位置
    BYTE E9Bit = 0xe;    //修正E9指令位置
    BYTE E9addres = 0xd; //E8的下一条地址（E9）的位置

    PBYTE CodeBegin = NULL;

    //需要执行的MesagesBox在机器中的地址
    DWORD ProgrameAddress = 0x74E5A790;
    //ShellCode的长度
    DWORD Lenshellcode = sizeof(ShellCode);

    LPVOID OrginFile = NULL;//FileBuffer
    LPVOID FileImage = NULL;//ImageBuffer
    LPVOID NewFile = NULL;//NewBuffer


    PIMAGE_DOS_HEADER pDh = NULL;
    PIMAGE_NT_HEADERS pN32h = NULL;
    PIMAGE_FILE_HEADER pFh = NULL;
    PIMAGE_OPTIONAL_HEADER pO32h = NULL;
    PIMAGE_OPTIONAL_HEADER32 pO32h_Real = NULL;
    PIMAGE_SECTION_HEADER pSh = NULL;


    DWORD FileSize;
    DWORD FileCopySize;
    DWORD NewFileCopySize;
    DWORD WriteSize;
    
    //需要写入的文件和写入ShellCode之后的文件
    LPSTR InFilePath ="D:\\justdo\\A\\fg.exe";
    LPSTR OutFilePath = "D:\\justdo\\A\\fg_add.exe";

    //加载需要写入的文件
    FileSize = ReadPEFile(InFilePath,&OrginFile);
    //将写入的文件拓展为内存中的状态
    FileCopySize = CopyFileBufferToImageBuffer(OrginFile,&FileImage);

    pDh = (PIMAGE_DOS_HEADER)FileImage;
    pN32h = (PIMAGE_NT_HEADERS)((DWORD64)pDh + pDh->e_lfanew);
    pFh = (PIMAGE_FILE_HEADER)&(pN32h->FileHeader);
    pO32h = (PIMAGE_OPTIONAL_HEADER)&(pN32h->OptionalHeader);
    pSh = (PIMAGE_SECTION_HEADER)((DWORD64)&(pN32h->OptionalHeader) + pFh->SizeOfOptionalHeader);
    pO32h_Real = (PIMAGE_OPTIONAL_HEADER32)pO32h;
    //判断第一个节是否有空间能存下ShellCode的大小
    //文件中对齐之后的节的大小 - 内存中未对齐前的节的大小(内存中的实际大小)
    if ((pSh->SizeOfRawData - pSh->Misc.VirtualSize) < Lenshellcode){
        printf("Can`t enough write shellcode!\n");
        free(OrginFile);
        free(FileImage);
        return FALSE;
    }
    
    //第一个节在内存中最后的有数据的位置
    //内存中的位置 + 第一个节的偏移值 + 第一个节内存中未对齐前的大小
    CodeBegin = (PBYTE)((DWORD64)FileImage + pSh->VirtualAddress + pSh->Misc.VirtualSize);

    printf("VirtualAddress: %x\n",pSh->VirtualAddress);
    printf("Misc.VirtualSize: %x\n",pSh->Misc.VirtualSize);
    printf("FileAlignment: %x\n",pO32h_Real->FileAlignment);
    printf("SectionAlignment: %x\n",pO32h_Real->SectionAlignment);
    printf("FileImage_Address: %x\n",(DWORD64)FileImage);
    printf("CodeBegin_Address: %x\n",CodeBegin);
    printf("CodeBegin_Address: %x\n",CodeBegin-(DWORD64)FileImage);
    printf("ImageBase_Address: %x\n",pO32h_Real->ImageBase);
    printf("E8: %x\n",*(PDWORD)(CodeBegin + E8Bit));
    printf("E9: %x\n",*(PDWORD)(CodeBegin + E9Bit));
    printf("AddressOfEntryPoint: %x\n",pO32h->AddressOfEntryPoint);
    
    memcpy(CodeBegin,ShellCode,Lenshellcode);

    //修正E8
    //E8Call = 需要执行的程序的地址 - ImageBase(实际运行的时候的内存地址) + (ShellCode中E9的起始位置 - 内存中的位置)
    //E8Call = 需要执行的程序的地址 - ImageBase + E8Call在内存中的相对偏移
    DWORD E8Call = ProgrameAddress - (pO32h_Real->ImageBase + ((DWORD64)((CodeBegin + E9addres) -(DWORD64)FileImage)));
    *(PDWORD)(CodeBegin + E8Bit) = E8Call;
    printf("E8Call:%x\n",E8Call);
    //修正E9
    DWORD E9Call = (pO32h_Real->ImageBase + pO32h->AddressOfEntryPoint) - (pO32h_Real->ImageBase + (DWORD64)((CodeBegin + Lenshellcode) - (DWORD64)FileImage));
    *(PDWORD)(CodeBegin + E9Bit) = E9Call;
    printf("E9Call:%x\n",E9Call);
    //修正OEP
    pO32h->AddressOfEntryPoint = (DWORD64)CodeBegin - (DWORD64)FileImage;

    NewFileCopySize = CopyImageBufferToNewBuffer(FileImage,&NewFile);

    WriteSize = MemeryTOFile(NewFile,NewFileCopySize,OutFilePath);

    free(OrginFile);
    free(FileImage);
    free(NewFile);
    return TRUE;

}
BOOL AddSection(){

    LPVOID FileBuffer = NULL;//FileBuffer
    LPVOID ImageBuffer = NULL;//ImageBuffer
    LPVOID NewBuffer = NULL;//NewBuffer
    //文件路径
    LPSTR FilePath ="D:\\justdo\\A\\PETooltest.exe";
    LPSTR FileName = "D:\\justdo\\A\\PETooltest_addsec.exe";

    PIMAGE_DOS_HEADER pDh = NULL;
    PIMAGE_NT_HEADERS pN32h = NULL;
    PIMAGE_FILE_HEADER pFh = NULL;
    PIMAGE_OPTIONAL_HEADER pO32h = NULL;
    PIMAGE_OPTIONAL_HEADER32 pO32h_Real = NULL;
    PIMAGE_SECTION_HEADER pSh = NULL;
    PIMAGE_SECTION_HEADER pSh_new = NULL;

    DWORD FileSize;
    DWORD FileCopySize;
    DWORD NewFileCopySize;
    DWORD WriteSize;

    PBYTE tempbuff = NULL;
    //传入文件路径和void**类型的待申请地址空间
    FileSize = ReadPEFile(FilePath,&FileBuffer);
    FileCopySize = CopyFileBufferToImageBuffer(FileBuffer,&ImageBuffer);

    pDh = (PIMAGE_DOS_HEADER)ImageBuffer;
    pN32h = (PIMAGE_NT_HEADERS)((DWORD64)pDh + pDh->e_lfanew);
    pFh = (PIMAGE_FILE_HEADER)&(pN32h->FileHeader);
    pO32h = (PIMAGE_OPTIONAL_HEADER)&(pN32h->OptionalHeader);
    pSh = (PIMAGE_SECTION_HEADER)((DWORD64)&(pN32h->OptionalHeader) + pFh->SizeOfOptionalHeader);
    pO32h_Real = (PIMAGE_OPTIONAL_HEADER32)pO32h;

    //节的数量
    DWORD NumSecs = pFh->NumberOfSections;

    //节结束的位置 节表结束到第一个节空白区的开始位置
    pSh_new = pSh + NumSecs;
    //写入节表的可用空间
    DWORD Ablespace = pO32h_Real->SizeOfHeaders - ((DWORD64)pSh - (DWORD64)ImageBuffer);
    //判断尝试写入的空间够不够两个节表的空间
    if (Ablespace < (IMAGE_SIZEOF_SECTION_HEADER * 2)){
        printf("Can`t write Section!\n");
        free(FileBuffer);
        free(ImageBuffer);
        exit(1);
    }
    //将第一个节表的数据复制到新的位置上
    // memcpy((PBYTE)pSh_new,(PBYTE)pSh,IMAGE_SIZEOF_SECTION_HEADER);
    *pSh_new = *pSh;
    //将新增节表后面覆盖40个字节的0
    memset((pSh_new + 1),0,IMAGE_SIZEOF_SECTION_HEADER);
    //修改新增节的名字
    BYTE NAME[IMAGE_SIZEOF_SHORT_NAME] = {".NewSec"};
    for (size_t i = 0; i < IMAGE_SIZEOF_SHORT_NAME; i++){
        pSh_new->Name[i] = NAME[i];
    }
    
    //增加的节的大小
    DWORD AddSecSize = 4000;
    ImageBuffer = realloc(ImageBuffer,AddSecSize);

    


    // NewFileCopySize = CopyImageBufferToNewBuffer(ImageBuffer,&NewBuffer);
    // WriteSize = MemeryTOFile(NewBuffer,NewFileCopySize,FileName);

    free(FileBuffer);
    free(ImageBuffer);
    // free(NewBuffer);
    return 0;


}
//传入对齐大小(Alignment)和真实大小(relsize) 返回应该对齐的大小
DWORD getAlign(int Alignment ,int relsize){
    return (relsize%Alignment > 0)?(relsize/Alignment + 1)*Alignment:Alignment;
}

int fun(){
    LPVOID OrginFile = NULL;//FileBuffer
    LPVOID FileImage = NULL;//ImageBuffer
    LPVOID NewFile = NULL;//NewBuffer

    //文件路径
    LPSTR FilePath ="D:\\justdo\\A\\ClickRun.exe";
    // LPSTR FilePath ="D:\\Tools\\crack reverse\\Hashyuan.exe";
    LPSTR FileName = "D:\\justdo\\A\\ClickRun_Copy.exe";

    //返回的文件大小
    DWORD FileSize;
    DWORD FileCopySize;
    DWORD NewFileCopySize;
    DWORD WriteSize;

    //传入文件路径和void**类型的待申请地址空间
    printf("*********************************************************\n");
    printf("ReadPEFile:\n");
    FileSize = ReadPEFile(FilePath,&OrginFile);
    printf("Writed file to buffer %d betys\n",FileSize);
    printf("*********************************************************\n");
    printf("CopyFileBufferToImageBuffer:\n");
    FileCopySize = CopyFileBufferToImageBuffer(OrginFile,&FileImage);
    printf("Copy file to MemoryImage %d bytes\n",FileCopySize);
    printf("*********************************************************\n");
    printf("CopyImageBufferToNewBuffer:\n");
    NewFileCopySize = CopyImageBufferToNewBuffer(FileImage,&NewFile);
    printf("Copy ImageBuffer to NewBuffer %d bytes\n",NewFileCopySize);
    printf("*********************************************************\n");
    printf("MemeryTOFile:\n");
    WriteSize = MemeryTOFile(NewFile,NewFileCopySize,FileName);
    printf("Write NewBuffer to DiskFile %d bytes\n",WriteSize);
    printf("*********************************************************\n");

    free(OrginFile);
    free(FileImage);
    free(NewFile);
    return 0;
}

DWORD Test(){
    LPVOID OrginFile = NULL;//FileBuffer
    LPVOID FileImage = NULL;//ImageBuffer
    // LPVOID NewFile = NULL;//NewBuffer

    //文件路径
    // LPSTR FilePath ="E:\\User\\Documents\\learn\\vs_learn\\C_Test\\word_test\\testod.exe";
    LPSTR FilePath ="D:\\User\\Documents\\learn\\VSCode\\CLanguage\\cTest\\src\\leaen\\testod.exe";

    //返回的文件大小
    DWORD FileSize;
    DWORD FileCopySize;
    // DWORD NewFileCopySize;
    // DWORD WriteSize;
    printf("*********************************************************\n");
    printf("ReadPEFile:\n");
    FileSize = ReadPEFile(FilePath,&OrginFile);
    printf("Writed file to buffer %d betys\n",FileSize);
    printf("*********************************************************\n");


    DWORD RAV =0x4004;
    DWORD FOA;
    FOA = RvaToFileOffset(OrginFile,RAV);
    printf("FOA: %x",FOA);

}

int main(int argc, char const *argv[])
{
    // fun();
    // Test();
    AddShellCode();
    return 0;
}
