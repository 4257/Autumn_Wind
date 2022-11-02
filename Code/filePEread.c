#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <winnt.h>


DWORD loadFile(const LPSTR file_path,LPVOID* file_buff){
    //文件指针
    FILE* pfile = NULL;
    //文件大小
    DWORD file_size = 0;
    //接受DWORD类型的返回值，判断
    DWORD flag = 0;

    if(!(pfile = fopen(file_path,"rb"))){
        printf("Can`t open the file!\n");
        return 0;
    };
    //将文件指针指向最后
    fseek(pfile,0,SEEK_END);
    //ftell函数获取文件指针当前的位置。相当于文件大小
    file_size = ftell(pfile);
    //将文件指针指向开头
    fseek(pfile,0,SEEK_SET);
    //判断传入的参数file_buff是否申请到内存
    if(!(*file_buff = malloc(file_size))){
		printf("Can`t allocation buff!\n");
		fclose(pfile);
		return 0;
    };
    
    flag = fread(*file_buff,file_size,sizeof(char),pfile);
    if (!flag)
    {
        printf("Can`t copy file to buff!\n");
        fclose(pfile);
        free(*file_buff);
        return 0;
    }
    //关闭文件
    fclose(pfile);
    return file_size;
}

DWORD CopyFileBufferToImageBuffer(LPVOID file_buff,LPVOID* image_buff){
    PIMAGE_DOS_HEADER pDh = NULL;
    PIMAGE_NT_HEADERS32 pNh = NULL;
    PIMAGE_FILE_HEADER pFh = NULL;
    PIMAGE_OPTIONAL_HEADER pO32h = NULL;
    PIMAGE_OPTIONAL_HEADER64 pO64h = NULL;
    PIMAGE_SECTION_HEADER pSh = NULL;
    // LPVOID image_buff = NULL;
    BYTE text[9] = {0};

    pDh = (PIMAGE_DOS_HEADER)file_buff;
    //判断是否位MZ标志位
    // printf("%p",pDh->e_magic);
    if (pDh->e_magic != IMAGE_DOS_SIGNATURE)
    {
		printf("Not a valid PE file! Error by Dos header!\n");
        free(file_buff);
		return 0;
    }

    pNh = (PIMAGE_NT_HEADERS32)((DWORD)pDh + pDh->e_lfanew);
    //判断是否为PE标志位
    if (pNh->Signature != IMAGE_NT_SIGNATURE)
    {
		printf("Not a valid PE file! Error by NT header!\n");
        free(file_buff);
		return 0;
    }

    pFh = (PIMAGE_FILE_HEADER)&(pNh->FileHeader);
    //判断是x86pe文件还是x64pe文件
    if (pFh->Machine == IMAGE_FILE_MACHINE_AMD64)
    {
        pO64h = (PIMAGE_OPTIONAL_HEADER64)&(pNh->OptionalHeader);
        if(!(*image_buff = malloc(pO64h->SizeOfImage))){
            printf("Can`t allocation buff!\n");
            free(*image_buff);
            return 0;
        }
        memset(*image_buff,0,sizeof(int));
        (*image_buff) = memcpy(*image_buff,file_buff,pO64h->SizeOfHeaders);
        for (size_t i = 1,j = 0; i <= pFh->NumberOfSections; i++)
        {
            pSh = (PIMAGE_SECTION_HEADER)((DWORD)pFh+sizeof(IMAGE_FILE_HEADER)+pFh->SizeOfOptionalHeader+j);
            memcpy((LPVOID)((DWORD)(*image_buff)+pSh->VirtualAddress),(LPVOID)((DWORD)file_buff+pSh->PointerToRawData),pSh->SizeOfRawData);
            j += 0x28;
        }
        // FILE* filetest;
        // filetest = fopen("D:\\justdo\\A\\imagebuff.txt","wb");
        // fwrite(image_buff,sizeof(char),pO64h->SizeOfImage,filetest);
        // fclose(filetest);
        return pO64h->SizeOfImage;
    }else if (pFh->Machine == IMAGE_FILE_MACHINE_I386)
    {
        pO32h = (PIMAGE_OPTIONAL_HEADER32)&(pNh->OptionalHeader);
        // printf("%p\n",pO32h->SizeOfImage);
        if(!(*image_buff = malloc(pO32h->SizeOfImage))){
            printf("Can`t allocation buff!\n");
            free(*image_buff);
            return 0;
        }
        memset(*image_buff,0,sizeof(int));
        *image_buff = memcpy(*image_buff,file_buff,pO32h->SizeOfHeaders);
        for (size_t i = 1,j = 0; i <= pFh->NumberOfSections; i++)
        {
            pSh = (PIMAGE_SECTION_HEADER)((DWORD)pFh+sizeof(IMAGE_FILE_HEADER)+pFh->SizeOfOptionalHeader+j);
            memcpy((LPVOID)((DWORD)(*image_buff)+pSh->VirtualAddress),(LPVOID)((DWORD)file_buff+pSh->PointerToRawData),pSh->SizeOfRawData);
            j += 0x28;
        }
        return pO32h->SizeOfImage;
    }
}

DWORD CopyImageBufferToNewBuffer(LPVOID pImageBuffer,LPVOID* pNewBuffer){
    PIMAGE_DOS_HEADER pDh = NULL;
    PIMAGE_NT_HEADERS32 pNh = NULL;
    PIMAGE_FILE_HEADER pFh = NULL;
    PIMAGE_OPTIONAL_HEADER pO32h = NULL;
    PIMAGE_OPTIONAL_HEADER64 pO64h = NULL;
    //最后一个节的位置
    PIMAGE_SECTION_HEADER lastSection = NULL;
    PIMAGE_SECTION_HEADER pSh = NULL;
    //节数
    DWORD numOFsections = 0;
    //IMAGE_BUFF计算的文件大小
    DWORD file_Size = 0;

    pDh = (PIMAGE_DOS_HEADER)pImageBuffer;
    pNh = (PIMAGE_NT_HEADERS32)((DWORD)pDh+pDh->e_lfanew);
    pFh = (PIMAGE_FILE_HEADER)&pNh->FileHeader;
    numOFsections = pFh->NumberOfSections - 1;
    lastSection = (PIMAGE_SECTION_HEADER)((DWORD)pFh+sizeof(IMAGE_FILE_HEADER)+pFh->SizeOfOptionalHeader+(numOFsections*sizeof(IMAGE_SECTION_HEADER)));
    if (numOFsections <= 1)
    {
        printf("File error!\n");
        exit(0);
    }
    // printf("%p\n",lastSection->PointerToRawData);
    // printf("%p\n",lastSection->SizeOfRawData);
    file_Size = (lastSection->PointerToRawData)+(lastSection->SizeOfRawData);
    // printf("%p\n",file_Size);
    if (pFh->Machine == IMAGE_FILE_MACHINE_AMD64){
        pO64h = (PIMAGE_OPTIONAL_HEADER64)&pNh->OptionalHeader;
        *pNewBuffer = malloc(file_Size);
        if (!(*pNewBuffer))
        {
            printf("Can`t allocation buff!\n");
            free(*pNewBuffer);
            return 0;   
        }
        memset(*pNewBuffer,0,sizeof(int));
        (*pNewBuffer) = memcpy(*pNewBuffer,pImageBuffer,pO64h->SizeOfHeaders);
        for (size_t i = 1,j = 0; i <= pFh->NumberOfSections; i++)
        {
            pSh = (PIMAGE_SECTION_HEADER)((DWORD)pFh+sizeof(IMAGE_FILE_HEADER)+pFh->SizeOfOptionalHeader+j);
            memcpy((LPVOID)((DWORD)(*pNewBuffer)+pSh->PointerToRawData),(LPVOID)((DWORD)pImageBuffer+pSh->VirtualAddress),pSh->SizeOfRawData);
            j += 0x28;
        }
        return file_Size;
    }else if (pFh->Machine == IMAGE_FILE_MACHINE_I386)
    {
        pO32h = (PIMAGE_OPTIONAL_HEADER32)&pNh->OptionalHeader;
        *pNewBuffer = malloc(file_Size);
        if (!(*pNewBuffer))
        {
            printf("Can`t allocation buff!\n");
            free(*pNewBuffer);
            return 0;   
        }
        memset(*pNewBuffer,0,sizeof(int));
        (*pNewBuffer) = memcpy(*pNewBuffer,pImageBuffer,pO32h->SizeOfHeaders);
        for (size_t i = 1,j = 0; i <= pFh->NumberOfSections; i++)
        {
            pSh = (PIMAGE_SECTION_HEADER)((DWORD)pFh+sizeof(IMAGE_FILE_HEADER)+pFh->SizeOfOptionalHeader+j);
            memcpy((LPVOID)((DWORD)(*pNewBuffer)+pSh->PointerToRawData),(LPVOID)((DWORD)pImageBuffer+pSh->VirtualAddress),pSh->SizeOfRawData);
            j += 0x28;
        }
        return file_Size;
    }  
}

DWORD saveFile(LPSTR newFile_path,LPVOID* filebuff,DWORD fileSize){
    FILE* filetest;
    filetest = fopen(newFile_path,"wb");
    fwrite(*filebuff,sizeof(char),fileSize,filetest);
    fclose(filetest);
    return 0;
}


int main(int argc, char const *argv[])
{
    const LPSTR file_path = "D:\\justdo\\A\\PETool.exe";
    LPSTR newFile_path = "D:\\justdo\\A\\newFilePETool.exe";
    LPVOID file_buff = NULL;
    LPVOID image_buff = NULL;
    LPVOID file_newBuff = NULL;

    DWORD fileSize = 0;
    DWORD NewfileSize = 0;
    DWORD flag = 0;

    fileSize = loadFile(file_path,&file_buff);
    printf("FILE_BUFF-Size:%p\n",fileSize);
    flag = CopyFileBufferToImageBuffer(file_buff,&image_buff);
    printf("IMAGE_BUFF-Size:%p\n",flag);
    NewfileSize = CopyImageBufferToNewBuffer(image_buff,&file_newBuff);
    printf("NEWFILE_BUFF-Size:%p\n",NewfileSize);

    saveFile(newFile_path,&file_newBuff,fileSize);



    free(file_newBuff);
    free(file_buff);
    free(image_buff);
    return 0;
}
