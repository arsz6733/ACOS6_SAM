
#include "ACOS6-SAM.h"


/*TODOs*/
/***
**Must implement WriteKey And WritePIN
**Must implement GenerateKey , encrypt , decrypt , diversify
**Must Read About SetKey And GetKey 
**Also Must implement Authentication 
**Must Test Diversify Keyindex input in variuos Situation
***/

//variable for dummy reading
uint8_t trash=0;
uint8_t TEMP=0;

//APDU structures
typedef struct{
	uint8_t CLA;
	uint8_t INS;
	uint8_t P1;
	uint8_t P2;
	uint8_t P3;
}APDU;
  

// reserved for future
typedef struct{
	uint8_t PIN_Identifier;
	uint8_t Error_Counter;
	uint16_t PIN_Value;
}PIN;


//TLV TAGS
#define TLV_TAG  0x62;
#define SizeOfTransparentEF_TAG  0x80;
#define SizeOfTransparentEF_LENGTH  0x02;
#define FDB_DCB_x_MRL_NOR_TAG  0x82;
#define FDB_LENGTH  0x01;
#define FDB_DCB_LENGTH  0x02;
#define FDB_DCB_xx_MRL_NOR_LENGTH  0x05;
#define FileID_TAG  0x83;
#define FileID_LENGTH  0x02;
#define ShortFileID_TAG  0x88;
#define ShortFileID_LENGTH  0x01;
#define LifeCycleStateInteger_TAG  0x8A;
#define LifeCycleStateInteger_LENGTH  0x01;
#define SecurityAttributeCompact_TAG  0x8C;
#define SecurityAttributeCompact_LENGTH  0x08;
#define SEFileID_TAG  0x8D;
#define SEFileID_LENGTH  0x02; 


void SendCommand(const APDU APDUtoSend);
void SendData(const uint8_t *data,uint8_t length);
void GetData(uint8_t *data,uint8_t length);
uint8_t GetByte(void);


SC_FuncPTR  SC_Functions;



SAMReplies SC_FuncPtInit(SC_FuncPTR func_ptr)
{
	if( func_ptr.SC_output == 0 || func_ptr.SC_input == 0 || func_ptr.SC_delay == 0){
		return SAM_Failed;
	}
	SC_Functions.SC_output = func_ptr.SC_output;
	SC_Functions.SC_input = func_ptr.SC_input;
	SC_Functions.SC_delay = func_ptr.SC_delay;
	
	return SAM_Success;
}

SAMReplies SC_CreateFile(FileTypes filetype,uint16_t FileID,uint8_t ShortID,uint16_t FileSize,uint8_t MRL,uint8_t NOR,LifeCycleStateInteger lcsi,uint16_t SEFileID,uint8_t DeleteSelf,uint8_t Terminate,uint8_t Activate,\
uint8_t Deactivate,uint8_t CreateDF,uint8_t CreateEF_Update_SetKey,uint8_t DeleteChild_Read)
{
	uint8_t temp_LCSI=0;
	uint8_t CreateFileData[50];
	APDU CreateFileAPDU;
	uint8_t length=2;
	
	
	switch(lcsi){
			case Creation:
				temp_LCSI = 0x01;
			break;
			case Initialization:
				temp_LCSI = 0x03;
			break;
			case Activated:
				temp_LCSI = 0x07;
			break;
			case Deactivated:
				temp_LCSI = 0x06;
			break;
			case Termination:
				temp_LCSI = 0x0F;
			break;
	}
	switch(filetype){
		case MF:
			CreateFileData[length]=	FDB_DCB_x_MRL_NOR_TAG;
			CreateFileData[++length]=	FDB_LENGTH;
		  CreateFileData[++length]= 0x3F;
			CreateFileData[++length]= FileID_TAG;
			CreateFileData[++length]= FileID_LENGTH;
			CreateFileData[++length]=	0x3F;
			CreateFileData[++length]=	0x00;
			if(ShortID!=0xFF){
				CreateFileData[++length]= ShortFileID_TAG;
				CreateFileData[++length]= ShortFileID_LENGTH;
				CreateFileData[++length]= ShortID;
			}
			 CreateFileData[++length]= LifeCycleStateInteger_TAG;
			 CreateFileData[++length]= LifeCycleStateInteger_LENGTH;
			 CreateFileData[++length]= temp_LCSI;
			 CreateFileData[++length]= SecurityAttributeCompact_TAG;
			 CreateFileData[++length]= SecurityAttributeCompact_LENGTH;
			 CreateFileData[++length]= 0x7F;
			 CreateFileData[++length]= DeleteSelf;
			 CreateFileData[++length]= Terminate;
			 CreateFileData[++length]= Activate;
			 CreateFileData[++length]= Deactivate;
			 CreateFileData[++length]= CreateDF;
			 CreateFileData[++length]= CreateEF_Update_SetKey;
			 CreateFileData[++length]= DeleteChild_Read;
			break;
		case DF:
			CreateFileData[length]=	FDB_DCB_x_MRL_NOR_TAG;
			CreateFileData[++length]=	FDB_LENGTH;
		  CreateFileData[++length]= 0x38;
			CreateFileData[++length]= FileID_TAG;
			CreateFileData[++length]= FileID_LENGTH;
			CreateFileData[++length]=	FileID >> 8;
			CreateFileData[++length]=	FileID & 0xFF;
			if(ShortID!=0xFF){
				CreateFileData[++length]= ShortFileID_TAG;
				CreateFileData[++length]= ShortFileID_LENGTH;
				CreateFileData[++length]= ShortID;
			}
			if(SEFileID!=0xFFFF){
				CreateFileData[++length]= SEFileID_TAG;
				CreateFileData[++length]= SEFileID_LENGTH;
				CreateFileData[++length]= SEFileID >> 8;
				CreateFileData[++length]= SEFileID & 0xFF;
			}
			 CreateFileData[++length]= LifeCycleStateInteger_TAG;
			 CreateFileData[++length]= LifeCycleStateInteger_LENGTH;
			 CreateFileData[++length]= temp_LCSI;
			 CreateFileData[++length]= SecurityAttributeCompact_TAG;
			 CreateFileData[++length]= SecurityAttributeCompact_LENGTH;
			 CreateFileData[++length]= 0x7F;
			 CreateFileData[++length]= DeleteSelf;
			 CreateFileData[++length]= Terminate;
			 CreateFileData[++length]= Activate;
			 CreateFileData[++length]= Deactivate;
			 CreateFileData[++length]= CreateDF;
			 CreateFileData[++length]= CreateEF_Update_SetKey;
			 CreateFileData[++length]= DeleteChild_Read;
			break;
		case TransparentEF:
			CreateFileData[length]=	FDB_DCB_x_MRL_NOR_TAG;
			CreateFileData[++length]=	FDB_LENGTH;
		  CreateFileData[++length]= 0x01;
			CreateFileData[++length]= FileID_TAG;
			CreateFileData[++length]= FileID_LENGTH;
			CreateFileData[++length]=	FileID >> 8;
			CreateFileData[++length]=	FileID & 0xFF;
			CreateFileData[++length]=	SizeOfTransparentEF_TAG;
			CreateFileData[++length]=	SizeOfTransparentEF_LENGTH;
			CreateFileData[++length]=	FileSize >> 8;
			CreateFileData[++length]=	FileSize & 0xFF;
			if(ShortID!=0xFF){
				CreateFileData[++length]= ShortFileID_TAG;
				CreateFileData[++length]= ShortFileID_LENGTH;
				CreateFileData[++length]= ShortID;
			}
		  CreateFileData[++length]= LifeCycleStateInteger_TAG;
		  CreateFileData[++length]= LifeCycleStateInteger_LENGTH;
		  CreateFileData[++length]= temp_LCSI;
		  CreateFileData[++length]= SecurityAttributeCompact_TAG;
		  CreateFileData[++length]= SecurityAttributeCompact_LENGTH;
		  CreateFileData[++length]= 0x7F;
		  CreateFileData[++length]= DeleteSelf;
		  CreateFileData[++length]= Terminate;
		  CreateFileData[++length]= Activate;
		  CreateFileData[++length]= Deactivate;
		  CreateFileData[++length]= CreateDF;
		  CreateFileData[++length]= CreateEF_Update_SetKey;
		  CreateFileData[++length]= DeleteChild_Read;
			break;
		case LinearFixedEF:
			CreateFileData[length]=	FDB_DCB_x_MRL_NOR_TAG;
			CreateFileData[++length]=	FDB_DCB_xx_MRL_NOR_LENGTH;
		  CreateFileData[++length]= 0x02;
		  CreateFileData[++length]= 0x00;
		  CreateFileData[++length]= 0x00;		
		  CreateFileData[++length]= MRL;		  
		  CreateFileData[++length]= NOR;
			CreateFileData[++length]= FileID_TAG;
			CreateFileData[++length]= FileID_LENGTH;
			CreateFileData[++length]=	FileID >> 8;
			CreateFileData[++length]=	FileID & 0xFF;
			if(ShortID!=0xFF){
				CreateFileData[++length]= ShortFileID_TAG;
				CreateFileData[++length]= ShortFileID_LENGTH;
				CreateFileData[++length]= ShortID;
			}
			 CreateFileData[++length]= LifeCycleStateInteger_TAG;
			 CreateFileData[++length]= LifeCycleStateInteger_LENGTH;
			 CreateFileData[++length]= temp_LCSI;
			 CreateFileData[++length]= SecurityAttributeCompact_TAG;
			 CreateFileData[++length]= SecurityAttributeCompact_LENGTH;
			 CreateFileData[++length]= 0x7F;
			 CreateFileData[++length]= DeleteSelf;
			 CreateFileData[++length]= Terminate;
			 CreateFileData[++length]= Activate;
			 CreateFileData[++length]= Deactivate;
			 CreateFileData[++length]= CreateDF;
			 CreateFileData[++length]= CreateEF_Update_SetKey;
			 CreateFileData[++length]= DeleteChild_Read;
			break;
		case LinearVariableEF:
			CreateFileData[length]=	FDB_DCB_x_MRL_NOR_TAG;
			CreateFileData[++length]=	FDB_DCB_xx_MRL_NOR_LENGTH;
		  CreateFileData[++length]= 0x04;
		  CreateFileData[++length]= 0x00;
		  CreateFileData[++length]= 0x00;		
		  CreateFileData[++length]= MRL;		  
		  CreateFileData[++length]= NOR;
			CreateFileData[++length]= FileID_TAG;
			CreateFileData[++length]= FileID_LENGTH;
			CreateFileData[++length]=	FileID >> 8;
			CreateFileData[++length]=	FileID & 0xFF;
			if(ShortID!=0xFF){
				CreateFileData[++length]= ShortFileID_TAG;
				CreateFileData[++length]= ShortFileID_LENGTH;
				CreateFileData[++length]= ShortID;
			}
			 CreateFileData[++length]= LifeCycleStateInteger_TAG;
			 CreateFileData[++length]= LifeCycleStateInteger_LENGTH;
			 CreateFileData[++length]= temp_LCSI;
			 CreateFileData[++length]= SecurityAttributeCompact_TAG;
			 CreateFileData[++length]= SecurityAttributeCompact_LENGTH;
			 CreateFileData[++length]= 0x7F;
			 CreateFileData[++length]= DeleteSelf;
			 CreateFileData[++length]= Terminate;
			 CreateFileData[++length]= Activate;
			 CreateFileData[++length]= Deactivate;
			 CreateFileData[++length]= CreateDF;
			 CreateFileData[++length]= CreateEF_Update_SetKey;
			 CreateFileData[++length]= DeleteChild_Read;
			break;
		case CyclicEF:
			CreateFileData[length]=	FDB_DCB_x_MRL_NOR_TAG;
			CreateFileData[++length]=	FDB_DCB_xx_MRL_NOR_LENGTH;
		  CreateFileData[++length]= 0x06;
		  CreateFileData[++length]= 0x00;
		  CreateFileData[++length]= 0x00;		
		  CreateFileData[++length]= MRL;		  
		  CreateFileData[++length]= NOR;
			CreateFileData[++length]= FileID_TAG;
			CreateFileData[++length]= FileID_LENGTH;
			CreateFileData[++length]=	FileID >> 8;
			CreateFileData[++length]=	FileID & 0xFF;
			if(ShortID!=0xFF){
				CreateFileData[++length]= ShortFileID_TAG;
				CreateFileData[++length]= ShortFileID_LENGTH;
				CreateFileData[++length]= ShortID;
			}
			 CreateFileData[++length]= LifeCycleStateInteger_TAG;
			 CreateFileData[++length]= LifeCycleStateInteger_LENGTH;
			 CreateFileData[++length]= temp_LCSI;
			 CreateFileData[++length]= SecurityAttributeCompact_TAG;
			 CreateFileData[++length]= SecurityAttributeCompact_LENGTH;
			 CreateFileData[++length]= 0x7F;
			 CreateFileData[++length]= DeleteSelf;
			 CreateFileData[++length]= Terminate;
			 CreateFileData[++length]= Activate;
			 CreateFileData[++length]= Deactivate;
			 CreateFileData[++length]= CreateDF;
			 CreateFileData[++length]= CreateEF_Update_SetKey;
			 CreateFileData[++length]= DeleteChild_Read;
			break;
		case InternalLinearVariableEF:
			CreateFileData[length]=	FDB_DCB_x_MRL_NOR_TAG;
			CreateFileData[++length]=	FDB_DCB_xx_MRL_NOR_LENGTH;
		  CreateFileData[++length]= 0x0C;
		  CreateFileData[++length]= 0x00;
		  CreateFileData[++length]= 0x00;		
		  CreateFileData[++length]= MRL;		  
		  CreateFileData[++length]= NOR;
			CreateFileData[++length]= FileID_TAG;
			CreateFileData[++length]= FileID_LENGTH;
			CreateFileData[++length]=	FileID >> 8;
			CreateFileData[++length]=	FileID & 0xFF;
			if(ShortID!=0xFF){
				CreateFileData[++length]= ShortFileID_TAG;
				CreateFileData[++length]= ShortFileID_LENGTH;
				CreateFileData[++length]= ShortID;
			}
			 CreateFileData[++length]= LifeCycleStateInteger_TAG;
			 CreateFileData[++length]= LifeCycleStateInteger_LENGTH;
			 CreateFileData[++length]= temp_LCSI;
			 CreateFileData[++length]= SecurityAttributeCompact_TAG;
			 CreateFileData[++length]= SecurityAttributeCompact_LENGTH;
			 CreateFileData[++length]= 0x7F;
			 CreateFileData[++length]= DeleteSelf;
			 CreateFileData[++length]= Terminate;
			 CreateFileData[++length]= Activate;
			 CreateFileData[++length]= Deactivate;
			 CreateFileData[++length]= CreateDF;
			 CreateFileData[++length]= CreateEF_Update_SetKey;
			 CreateFileData[++length]= DeleteChild_Read;
			break;
		case InternalCyclicEF:
			CreateFileData[length]=	FDB_DCB_x_MRL_NOR_TAG;
			CreateFileData[++length]=	FDB_DCB_xx_MRL_NOR_LENGTH;
			CreateFileData[++length]= 0x0E;
			CreateFileData[++length]= 0x00;
			CreateFileData[++length]= 0x00;		
			CreateFileData[++length]= MRL;		  
			CreateFileData[++length]= NOR;
			CreateFileData[++length]= FileID_TAG;
			CreateFileData[++length]= FileID_LENGTH;
			CreateFileData[++length]=	FileID >> 8;
			CreateFileData[++length]=	FileID & 0xFF;
			if(ShortID!=0xFF){
				CreateFileData[++length]= ShortFileID_TAG;
				CreateFileData[++length]= ShortFileID_LENGTH;
				CreateFileData[++length]= ShortID;
			}
			 CreateFileData[++length]= LifeCycleStateInteger_TAG;
			 CreateFileData[++length]= LifeCycleStateInteger_LENGTH;
			 CreateFileData[++length]= temp_LCSI;
			 CreateFileData[++length]= SecurityAttributeCompact_TAG;
			 CreateFileData[++length]= SecurityAttributeCompact_LENGTH;
			 CreateFileData[++length]= 0x7F;
			 CreateFileData[++length]= DeleteSelf;
			 CreateFileData[++length]= Terminate;
			 CreateFileData[++length]= Activate;
			 CreateFileData[++length]= Deactivate;
			 CreateFileData[++length]= CreateDF;
			 CreateFileData[++length]= CreateEF_Update_SetKey;
			 CreateFileData[++length]= DeleteChild_Read;
			break;
	}

	CreateFileAPDU.CLA = 0x00;
	CreateFileAPDU.INS = 0xE0;
	CreateFileAPDU.P1 = 0x00;
	CreateFileAPDU.P2 = 0x00;
	CreateFileAPDU.P3 = length + 1;

	CreateFileData[0] = TLV_TAG;
	CreateFileData[1] = length - 1;
	
	SendCommand(CreateFileAPDU);
	
	if(CreateFileAPDU.INS!=GetByte())  ///Waiting For Procedure Byte 
		return SAM_Failed;
	
	SendData(CreateFileData,length+1);
	//debugging
//		TEMP=GetByte();
//	UARTPutChar(UART_0,TEMP);
//	TEMP=GetByte();
//	UARTPutChar(UART_0,TEMP);
	if(GetByte()!=0x90)
		return SAM_Failed;
	if(GetByte()!=0x00)
		return SAM_Failed;

	
	return SAM_Success;
}


SAMReplies SC_SelectFile(uint16_t FileID)
{	
	APDU SelectFileAPDU;
	uint8_t SelectFileData[4];
	
	
	SelectFileAPDU.CLA = 0x00;
	SelectFileAPDU.INS = 0xA4;
	SelectFileAPDU.P1 = 0x00;
	SelectFileAPDU.P2 = 0x00;
	SelectFileAPDU.P3 = 0x02;
	
	SelectFileData[0] = FileID >> 8;
	SelectFileData[1] = FileID & 0xFF;
	
	SendCommand(SelectFileAPDU);

	if(SelectFileAPDU.INS!=GetByte())  ///Waiting For Procedure Byte 
		return SAM_Failed;
	
	SendData(SelectFileData,2);
	

	if(GetByte()!=0x61)
		return SAM_Failed;
	// SW2 not important
	TEMP=GetByte();
	
	return SAM_Success;
}

SAMReplies SC_UpdateRecord(Record_Base recordbase,uint8_t RecordIndex,uint8_t NumberOfBytesToWrite,uint8_t* BytesToWrite)
{
	APDU UpdateRecordAPDU;

	
	UpdateRecordAPDU.CLA = 0x00;
	UpdateRecordAPDU.INS = 0xDC;
	if(recordbase == refrence_record_index_by_RecordIndex){
	UpdateRecordAPDU.P1 = RecordIndex;
	UpdateRecordAPDU.P2 = (uint8_t)refrence_record_index_by_RecordIndex;
	}
	else {
	UpdateRecordAPDU.P1 = 0x00;
	UpdateRecordAPDU.P2 = (uint8_t)recordbase;
	}
	UpdateRecordAPDU.P3 = NumberOfBytesToWrite;
	
	SendCommand(UpdateRecordAPDU);
		
	if(UpdateRecordAPDU.INS!=GetByte())
		return SAM_Failed;
	
	SendData(BytesToWrite,NumberOfBytesToWrite);

	if(GetByte()!=0x90)
		return SAM_Failed;
	if(GetByte()!=0x00)
		return SAM_Failed;
	
	return SAM_Success;
}


SAMReplies SC_ReadRecord(Record_Base recordbase,uint8_t RecordIndex,uint8_t NumberOfBytesToRead,uint8_t* BytesToRead)
{
	APDU ReadRecordAPDU;

	
	ReadRecordAPDU.CLA = 0x00;
	ReadRecordAPDU.INS = 0xB2;
	if(recordbase == refrence_record_index_by_RecordIndex){
	ReadRecordAPDU.P1 = RecordIndex;
	ReadRecordAPDU.P2 = (uint8_t)refrence_record_index_by_RecordIndex;
	}
	else {
	ReadRecordAPDU.P1 = 0x00;
	ReadRecordAPDU.P2 = (uint8_t)recordbase;
	}
	ReadRecordAPDU.P3 = NumberOfBytesToRead;
	
	SendCommand(ReadRecordAPDU);
		
	if(ReadRecordAPDU.INS!=GetByte())
		return SAM_Failed;
	
	GetData(BytesToRead,NumberOfBytesToRead);
	
	if(GetByte()!=0x90)
		return SAM_Failed;
	if(GetByte()!=0x00)
		return SAM_Failed;
	
	return SAM_Success;
}

SAMReplies SC_AppendRecord(uint8_t NumberOfBytesToWrite,uint8_t* BytesToWrite)
{
	APDU AppendRecordAPDU;

	
	AppendRecordAPDU.CLA = 0x00;
	AppendRecordAPDU.INS = 0xE2;
	AppendRecordAPDU.P1 = 0x00;
	AppendRecordAPDU.P2 = 0x00;
	AppendRecordAPDU.P3 = NumberOfBytesToWrite;
	
	SendCommand(AppendRecordAPDU);
		
	if(AppendRecordAPDU.INS!=GetByte())
		return SAM_Failed;
	
	SendData(BytesToWrite,NumberOfBytesToWrite);
	
	if(GetByte()!=0x90)
		return SAM_Failed;
	if(GetByte()!=0x00)
		return SAM_Failed;
	
	return SAM_Success;
}

SAMReplies SC_DeleteFiles(File_To_Be_Deleted FTBD,uint16_t FileID)
{
	APDU DeleteFileAPDU;
	uint8_t DeleteFileData[4];
	
	
	DeleteFileAPDU.CLA = 0x00;
	DeleteFileAPDU.INS = 0xE4;
	DeleteFileAPDU.P1 = 0x00;
	DeleteFileAPDU.P2 = 0x00;
	switch(FTBD){
		case Delete_The_Currently_Selected_File:
				DeleteFileAPDU.P3 = (uint8_t)Delete_The_Currently_Selected_File;
				
				SendCommand(DeleteFileAPDU);
				
				if(GetByte()!=0x90)
					return SAM_Failed;
				if(GetByte()!=0x00)
					return SAM_Failed;
		
		break;
		case Delete_The_File_By_FileID:
				DeleteFileAPDU.P3 = (uint8_t)Delete_The_File_By_FileID;
				
				SendCommand(DeleteFileAPDU);
				
				if(DeleteFileAPDU.INS!=GetByte())
					return SAM_Failed;
				
				DeleteFileData[0] = FileID >> 8;
				DeleteFileData[1] = FileID & 0xFF;
				
				SendData(DeleteFileData,2);
				
				if(GetByte()!=0x90)
					return SAM_Failed;
				if(GetByte()!=0x00)
					return SAM_Failed;
		
		break;
	}
	return SAM_Success;
}
SAMReplies SC_ClearCard(void)
{
	APDU ClearCardAPDU;
	
	
	ClearCardAPDU.CLA = 0x80;
	ClearCardAPDU.INS = 0x30;
	ClearCardAPDU.P1 = 0x00;
	ClearCardAPDU.P2 = 0x00;
	ClearCardAPDU.P2 = 0x00;
	
	SendCommand(ClearCardAPDU);
	//procedure Bytes = Trash
	trash=GetByte();
	trash=GetByte();
	
	
	if(GetByte()!=0x90)
		return SAM_Failed;
	if(GetByte()!=0x00)
		return SAM_Failed;

	return SAM_Success;
}

SAMReplies SC_GetResponse(uint8_t Length,uint8_t* Data)
{
	APDU GetResponseAPDU;


	GetResponseAPDU.CLA = 0x00;
	GetResponseAPDU.INS = 0xC0;
	GetResponseAPDU.P1 = 0x00;
	GetResponseAPDU.P2 = 0x00;
	GetResponseAPDU.P3 = Length;
	
	SendCommand(GetResponseAPDU);

	if(GetResponseAPDU.INS!=GetByte())
		return SAM_Failed;
	
	GetData(Data,Length);
	
	if(GetByte()!=0x90)
		return SAM_Failed;
	if(GetByte()!=0x00)
		return SAM_Failed;
	
	return SAM_Success;
}
SAMReplies SC_CreateMF(void)
{
	return SC_CreateFile(MF,0x3F00,0xFF,0xFFFF,0xFF,0xFF,Creation,0xFFFF,00,00,00,00,00,00,00);
}
SAMReplies SC_CreateDF(uint16_t FileID)
{
	return SC_CreateFile(DF,FileID,0xFF,0xFFFF,0xFF,0xFF,Creation,0xFFFF,00,00,00,00,00,00,00);
}


SAMReplies SC_CreateLinearFixedEF(uint16_t FileID,uint8_t MaximumRecordLength,uint8_t NumberOfRecords)
{
	return SC_CreateFile(LinearFixedEF,FileID,0xff,0xffff,MaximumRecordLength,NumberOfRecords,Creation,0xFFFF,00,00,00,00,00,00,00);
}

SAMReplies SC_GenerateKey(uint8_t KeyIndex,uint8_t* PlainText,uint8_t* Key)
{
	APDU GenerateKeyAPDU;
	SAMReplies result;
	int i;
	
	
	GenerateKeyAPDU.CLA = 0x80;
	GenerateKeyAPDU.INS = 0x88;
	GenerateKeyAPDU.P1 = 0x00;
	GenerateKeyAPDU.P2 = KeyIndex;
	GenerateKeyAPDU.P3 = 0x08;
	
	SendCommand(GenerateKeyAPDU);
	
	if(GenerateKeyAPDU.INS!=GetByte())
		return SAM_Failed;
	
	SendData(PlainText,8);

	if(GetByte()!=0x61)
		return SAM_Failed;
	if(GetByte()!=0x08)
		return SAM_Failed;

	
	SC_Functions.SC_delay(50);
	
	result=SC_GetResponse(8,Key);
	
	if(result==SAM_Failed)
		return SAM_Failed;
	

	SC_Functions.SC_delay(50);
	
	GenerateKeyAPDU.CLA = 0x80;
	GenerateKeyAPDU.INS = 0x88;
	GenerateKeyAPDU.P1 = 0x00;
	GenerateKeyAPDU.P2 = KeyIndex;
	GenerateKeyAPDU.P3 = 0x08;
	
	SendCommand(GenerateKeyAPDU);
	
	if(GenerateKeyAPDU.INS!=GetByte())
		return SAM_Failed;
	//Bit Wise Complement as said in Datasheet
	for(i=8;i<16;i++)
	PlainText[i]=~PlainText[i];
	
	SendData(&(PlainText[8]),8);

	if(GetByte()!=0x61)
		return SAM_Failed;
	if(GetByte()!=0x08)
		return SAM_Failed;
	
	SC_Functions.SC_delay(50);
	
	return SC_GetResponse(8,&(Key[8]));
}
SAMReplies SC_DiversifyKeyData(TargetKies targetkies,uint8_t KeyIndex,uint8_t* Data)
{
	APDU DiversifyKeyDataAPDU;

	
	DiversifyKeyDataAPDU.CLA = 0x80;
	DiversifyKeyDataAPDU.INS = 0x72;
	if(targetkies == BulkEncryptionKey){
		DiversifyKeyDataAPDU.P1 = BulkEncryptionKey;
		DiversifyKeyDataAPDU.P2 = KeyIndex;
		DiversifyKeyDataAPDU.P3 = 0x00;
		
		SendCommand(DiversifyKeyDataAPDU);

		if(GetByte()!=0x90)
			return SAM_Failed;
		if(GetByte()!=0x00)
			return SAM_Failed;		
		
		return SAM_Success;
	}
	else{
		DiversifyKeyDataAPDU.P1 = (uint8_t)targetkies;
		DiversifyKeyDataAPDU.P2 = KeyIndex;
		DiversifyKeyDataAPDU.P3 = 0x08;
		
		SendCommand(DiversifyKeyDataAPDU);
		
		if(DiversifyKeyDataAPDU.INS!=GetByte())
			return SAM_Failed;
		
		SendData(Data,0x08);
		
		if(GetByte()!=0x90)
			return SAM_Failed;
		if(GetByte()!=0x00)
			return SAM_Failed;	
	
		return 	SAM_Success;
	}
}

SAMReplies Sc_Encrypt(Encryption_Decryption_Modes modes,Encryption_Decryption_Keis keis,uint8_t LengthOfPlainText,uint8_t* PlainText,uint8_t* EncryptedData)
{
	APDU EncryptAPDU;
	uint8_t length=0;
	SAMReplies result;
	
		
	EncryptAPDU.CLA = 0x80;
	EncryptAPDU.INS = 0x74;
	EncryptAPDU.P1 = (uint8_t)modes;
	
	if(keis == ENC_Sc_Ks){
		EncryptAPDU.P2 = (uint8_t)keis;
		EncryptAPDU.P3 = 0x00;
		
		SendCommand(EncryptAPDU);
			
		if(GetByte()!=0x61)
			return SAM_Failed;
		length = GetByte();
		
		result=SC_GetResponse(length,EncryptedData);
		
		if(result == SAM_Failed)
			return SAM_Failed;

		return SAM_Success;
	}
	else{
		EncryptAPDU.P2 = (uint8_t)keis;
		EncryptAPDU.P3 = LengthOfPlainText;
			
		SendCommand(EncryptAPDU);

		if(EncryptAPDU.INS!=GetByte())
			return SAM_Failed;
		
		SendData(PlainText,LengthOfPlainText);
		
		if(GetByte()!=0x61)
			return SAM_Failed;
		length = GetByte();
		
		result=SC_GetResponse(length,EncryptedData);
		
		if(result == SAM_Failed)
			return SAM_Failed;
		
		return SAM_Success;
	}
}

SAMReplies Sc_Decrypt(Encryption_Decryption_Modes modes,Encryption_Decryption_Keis keis,uint8_t LengthOfPlainText,uint8_t* PlainText,uint8_t* EncryptedData)
{
	APDU DecryptAPDU;
	uint8_t length=0;
	SAMReplies result;
	
	
//A Copy of Encrypt Function	
	DecryptAPDU.CLA = 0x80;
	DecryptAPDU.INS = 0x76;
	DecryptAPDU.P1 = (uint8_t)modes;
	
	if(keis == ENC_Sc_Ks){	
		DecryptAPDU.P2 = (uint8_t)keis;
		DecryptAPDU.P3 = 0x00;
		
		SendCommand(DecryptAPDU);
			
		if(GetByte()!=0x61)
			return SAM_Failed;
		length = GetByte();
		
		result=SC_GetResponse(length,EncryptedData);
		
		if(result == SAM_Failed)
			return SAM_Failed;

		return SAM_Success;
	}
	else{
		DecryptAPDU.P2 = (uint8_t)keis;
		DecryptAPDU.P3 = LengthOfPlainText;
			
		SendCommand(DecryptAPDU);

		if(DecryptAPDU.INS!=GetByte())
			return SAM_Failed;
		
		SendData(PlainText,LengthOfPlainText);
		
		if(GetByte()!=0x61)
			return SAM_Failed;
		length = GetByte();
		
		result=SC_GetResponse(length,EncryptedData);
		
		if(result == SAM_Failed)
			return SAM_Failed;
		
		return SAM_Success;
	}
}

void SendCommand(const APDU APDUtoSend){
	SC_Functions.SC_output(&APDUtoSend.CLA,1);
	SC_Functions.SC_output(&APDUtoSend.INS,1);
	SC_Functions.SC_output(&APDUtoSend.P1,1);
	SC_Functions.SC_output(&APDUtoSend.P2,1);
	SC_Functions.SC_output(&APDUtoSend.P3,1);
}
void SendData(const uint8_t *data,uint8_t length){
	int i=0;
		for(i=0;i<length;i++)
			SC_Functions.SC_output(&data[i],1);
}
uint8_t GetByte(void){
	return SC_Functions.SC_input();
}

void GetData(uint8_t *data,uint8_t length){
	int i=0;
		for(i=0;i<length;i++)
			data[i]=SC_Functions.SC_input();
}