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
    // PIMAGE_NT_HEADERS64 pN64h = NULL;
    PIMAGE_FILE_HEADER pFh = NULL;
    PIMAGE_OPTIONAL_HEADER pO32h = NULL;
    // PIMAGE_OPTIONAL_HEADER64 pO64h = NULL;
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
    printf("Count + Size_Header: %d\n",Size_memcpy_Count);


    //循环读取pFileImage中已加载的节表的数据 并加载到pImageBuffer中
    //节表固定40(0x28)字节 节的数量为pFh->NumberOfSections
    for (int i = 1,j = 0; i <= pFh->NumberOfSections; i++){
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
    DWORD Size_memcpy_Count;
    Size_memcpy_Count += Size_Header;

    //循环复制节的数据到 Newbuffer
    for (size_t i = 0; i < pFh->NumberOfSections; i++){
        DWORD Size_Sections = pSh->SizeOfRawData;
        memcpy((LPVOID)((DWORD64)*pNewBuffer + (pSh->PointerToRawData)), (LPVOID)((DWORD64)pImageBuffer + pSh->VirtualAddress), Size_Sections);
        pSh ++;
        Size_memcpy_Count += Size_Sections;
    }
    
    return Size_memcpy_Count;
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
    LPVOID OrginFile = NULL;//FileBuffer
    LPVOID FileImage = NULL;//ImageBuffer
    LPVOID NewFile = NULL;//NewBuffer

    //文件路径
    // LPSTR FilePath ="D:\\justdo\\A\\PETool.exe";
    LPSTR FilePath ="D:\\Tools\\crack reverse\\Hashyuan.exe";

    //返回的文件大小
    DWORD FileSize;
    DWORD FileCopySize;
    DWORD NewFileCopySize;

    //传入文件路径和void**类型的待申请地址空间
    FileSize = ReadPEFile(FilePath,&OrginFile);
    printf("writed file to buffer %d betys\n",FileSize);
    printf("*********************************************************\n");
    FileCopySize = CopyFileBufferToImageBuffer(OrginFile,&FileImage);
    printf("Copy file to MemoryImage %d bytes\n",FileCopySize);
    printf("*********************************************************\n");
    NewFileCopySize = CopyImageBufferToNewBuffer(FileImage,&NewFile);
    printf("Copy ImageBuffer to NewBuffer %d bytes\n",NewFileCopySize);
    printf("*********************************************************\n");


    free(OrginFile);
    free(FileImage);
    free(NewFile);
    return 0;
}
