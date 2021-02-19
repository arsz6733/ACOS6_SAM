
#include <stdint.h>

typedef void (*SC_ouput_fn)(const uint8_t *data, uint32_t len);
typedef uint8_t (*SC_input_fn)(void);
typedef void (*SC_delay_ms_fn)(uint32_t ms);

typedef struct{
	SC_ouput_fn SC_output;
	SC_input_fn SC_input;
	SC_delay_ms_fn SC_delay;	
}SC_FuncPTR;

//Function Returns
typedef enum{
	SAM_Success=1,
	SAM_Failed,
	SAM_IncompatibleArguments
}SAMReplies;

//Argument Enums
typedef enum{
	MF = 0x3f,
	DF = 0x38,
	TransparentEF = 0x01,
	LinearFixedEF = 0x02,
	LinearVariableEF = 0x04,
	CyclicEF = 0x06,
	InternalLinearVariableEF = 0x0c,   //KEY EF
	InternalCyclicEF = 0x0E   //Purse EF
}FileTypes;

typedef enum{
	Creation = 0x01,
	Initialization = 0x03,
	Activated = 0x05,
	Deactivated = 0x06,
	Termination = 0x0F
}LifeCycleStateInteger;

typedef enum{
	refrence_1st_record = 0x00,
	reftence_last_record = 0x01,
	refrence_next_record = 0x02,
	refrence_previous_record = 0x03,
	refrence_record_index_by_RecordIndex = 0x04
}Record_Base;

typedef enum{
	SecretKey = 0x01,
	AccountKey = 0x02,
	TerminalKey = 0x03,
	CardKey = 0x04,
	BulkEncryptionKey = 0x05,
	InitialVector = 0x06
}TargetKies;

typedef enum{
	ECB_Mode_TripleDES = 0x00,
	ECB_Mode_SingleDES = 0x01,
	CBC_Mode_TripleDES = 0x02,
	CBC_Mode_SingleDES = 0x03,
	RetialMAC_Mode_TripleDES = 0x04,
	RetialMAC_Mode_SingleDES = 0x05,
	MAC_Mode_TripleDES = 0x06,
	MAC_Mode_SingleDES = 0x07,
	PrepareACOS3_SM_Mode_TripleDES = 0x08,
	PrepareACOS3_SM_Mode_SingleDES = 0x09
}Encryption_Decryption_Modes;

typedef enum{
	Session_Key = 0x01,
	Diversified_Key = 0x02,
	BulkEncryption_Key = 0x03,
	ENC_Sc_Ks = 0x0
}Encryption_Decryption_Keis;

typedef enum{
	Delete_The_File_By_FileID = 0x02,
	Delete_The_Currently_Selected_File = 0x00
}File_To_Be_Deleted;



//Compatible with iso7816-4

/*
*****Arguments Discription**********

// FileID Can't be 3FFF or FFFF
// FileIF for MF should be 3F00
// ShortID Should be FF to be NULL 
// MaximumRecordLength & NumberofRecords doesn't affect on MF & DF & Transparent EF 
// fileSize only affect on Transparent EF 
// SEFileID is only for DF  ---  Should be FFFF to be NULL
// Values of arguments DeleteSelf,Terminate,Activated,Deactivated,CreateDF,CreateEF_Update_SetKey,DeleteChild_Read --> NoCondition(00) NeverAllow(FF) or SERecord
*/

/*
pass Platform specific functions
*/
SAMReplies SC_FuncPtInit(SC_FuncPTR func_ptr);  

SAMReplies SC_CreateFile(FileTypes,uint16_t FileID,uint8_t ShortID,uint16_t FileSize,uint8_t MaximumRecordLength,uint8_t NumberOfRecords,LifeCycleStateInteger,uint16_t SEFileID,uint8_t DeleteSelf,uint8_t Terminate,uint8_t Activate,\
uint8_t Deactivate,uint8_t CreateDF,uint8_t CreateEF_Update_SetKey,uint8_t DeleteChild_Read);

//Simple MF  ID=0x3F00  LCSI = Creation
SAMReplies SC_CreateMF(void);

//Simple DF  NO ShortID - NO SecurityAttribute LCSI = Creation
SAMReplies SC_CreateDF(uint16_t FileID);

//Simple LinearFixedEF NO SecurityAttribute LCSI = Creation
SAMReplies SC_CreateLinearFixedEF(uint16_t FileID,uint8_t MaximumRecordLength,uint8_t NumberOfRecords);

SAMReplies SC_SelectFile(uint16_t FileID);

SAMReplies SC_UpdateRecord(Record_Base ,uint8_t RecordIndex,uint8_t LengthOfDataToWrite,uint8_t* Data);

SAMReplies SC_ReadRecord(Record_Base ,uint8_t RecordIndex,uint8_t LengthOfDataToRead,uint8_t* Data);

SAMReplies SC_AppendRecord(uint8_t LengthOfDataToWrite,uint8_t* Data);

SAMReplies SC_DeleteFiles(File_To_Be_Deleted,uint16_t FileID);

SAMReplies SC_ClearCard(void);

SAMReplies SC_GetResponse(uint8_t Length,uint8_t* Data);

/// Key shoulb be 16 Byte Also PlainText Should be 16Byte
SAMReplies SC_GenerateKey(uint8_t KeyIndex,uint8_t* PlainText,uint8_t* Key);
/*
/// Key index -> Bit7=0 if global  Bit7=1 if Local  Bit5,6=0 Reserved for Future   Bit0,1,2,3,4=Key index
/// 8Byte Client Card Deviation Data  for 	SecretKey,	AccountKey, 	TerminalKey ,	CardKey
/// No Data for BulkEncryption
/// 8Byte DES/3DES CBC InitialVector
*/
SAMReplies SC_DiversifyKeyData(TargetKies,uint8_t KeyIndex,uint8_t* Data);


SAMReplies Sc_Encrypt(Encryption_Decryption_Modes,Encryption_Decryption_Keis,uint8_t LengthOfPlainText,uint8_t* PlainText,uint8_t* EncryptedData);


SAMReplies Sc_Decrypt(Encryption_Decryption_Modes,Encryption_Decryption_Keis,uint8_t LengthOfEncryptedData,uint8_t* EncryptedData,uint8_t* Ciphertex);
