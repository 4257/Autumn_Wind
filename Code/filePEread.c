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
    }
    printf("malloc %d bytes\n",fileSize);

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
    PIMAGE_NT_HEADERS64 pN64h = NULL;
    PIMAGE_FILE_HEADER pFh = NULL;
    PIMAGE_OPTIONAL_HEADER pO32h = NULL;
    PIMAGE_OPTIONAL_HEADER64 pO64h = NULL;
    PIMAGE_SECTION_HEADER pSh = NULL;

    //将FileBuffer指向DOS头 
    pDh = (PIMAGE_DOS_HEADER)pFileBuffer;
    if(pDh->e_magic != IMAGE_DOS_SIGNATURE){
        printf("Not a valid PE file! Error by Dos header!\n");
        exit(1);
    }

    //DOS头加上DOS头偏移找到NT头
    pN32h = (PIMAGE_NT_HEADERS)((DWORD)pDh + pDh->e_lfanew);
    //判断软件的IMAGE_NT_SIGNATURE
    if (pN32h->Signature != IMAGE_NT_SIGNATURE){
        printf("Not a valid PE file! Error by NT header!\n");
        exit(1);
    }

    pFh = (PIMAGE_FILE_HEADER)&(pN32h->FileHeader);
    //判断软件是64位还是32位
    if (pFh->Machine == IMAGE_FILE_MACHINE_AMD64){
        pN64h = (PIMAGE_NT_HEADERS)((DWORD)pDh + pDh->e_lfanew);
        pFh = (PIMAGE_FILE_HEADER)&(pN64h->FileHeader);
        pO64h = (PIMAGE_OPTIONAL_HEADER64)&(pN64h->OptionalHeader);
        DWORD Size_Image;
        Size_Image = pO64h->SizeOfImage;
        printf("SizeOfImage: %d",Size_Image);
        DWORD Size_Header;
        Size_Header = pO64h ->SizeOfHeaders;
        printf("SizeOfImage: %d",Size_Header);
    }else if(pFh->Machine == IMAGE_FILE_MACHINE_I386){
        pN32h = (PIMAGE_NT_HEADERS)((DWORD)pDh + pDh->e_lfanew);
        pFh = (PIMAGE_FILE_HEADER)&(pN32h->FileHeader);
        pO32h = (PIMAGE_OPTIONAL_HEADER64)&(pN32h->OptionalHeader);
    }
    
    
    

}


//**************************************************************************
//CopyImageBufferToNewBuffer:将ImageBuffer中的数据复制到新的缓冲区
//参数说明：
//pImageBuffer ImageBuffer指针
//pNewBuffer NewBuffer指针
//返回值说明：
//读取失败返回0  否则返回复制的大小
//**************************************************************************
DWORD CopyImageBufferToNewBuffer(IN LPVOID pImageBuffer,OUT LPVOID* pNewBuffer);


//**************************************************************************
//MemeryTOFile:将内存中的数据复制到文件
//参数说明：
//pMemBuffer 内存中数据的指针
//size 要复制的大小
//lpszFile 要存储的文件路径
//返回值说明：
//读取失败返回0  否则返回复制的大小
//**************************************************************************
BOOL MemeryTOFile(IN LPVOID pMemBuffer,IN size_t size,OUT LPSTR lpszFile);


//**************************************************************************
//RvaToFileOffset:将内存偏移转换为文件偏移
//参数说明：
//pFileBuffer FileBuffer指针
//dwRva RVA的值
//返回值说明：
//返回转换后的FOA的值  如果失败返回0
//**************************************************************************
DWORD RvaToFileOffset(IN LPVOID pFileBuffer,IN DWORD dwRva);

int main(int argc, char const *argv[])
{
    LPVOID OrginFile = NULL;
    LPVOID FileImage = NULL;
    LPVOID NewFile = NULL;   

    //文件路径
    LPSTR FilePath ="D:/justdo/A/PETool.exe";

    //返回的文件大小
    DWORD FileSize;

    //传入文件路径和void**类型的待申请地址空间
    FileSize= ReadPEFile(FilePath,&OrginFile);
    printf("writed file %d betys\n",FileSize);

    CopyFileBufferToImageBuffer(OrginFile,&FileImage);

    free(OrginFile);
    return 0;
}
