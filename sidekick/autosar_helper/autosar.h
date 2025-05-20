# define STD_HIGH     1u
# define STD_LOW      0u

# define STD_ACTIVE   1u
# define STD_IDLE     0u

# define STD_ON       1u
# define STD_OFF      0u
typedef unsigned int uint;
typedef unsigned char uint8;
typedef char int8;
typedef unsigned short uint16;
typedef int uint32;
typedef short int16;
typedef unsigned long long uint64;
typedef long long int64;
typedef unsigned int implementation_specific;
typedef char* string;

typedef uint8 Std_TransformerErrorCode;
typedef uint8 PNCHandleType;
typedef uint8 NetworkHandleType;
typedef uint16 PduIdType;
typedef uint16 CbkHandleIdType;
typedef uint32 PduLengthType;
typedef int sint32;
typedef long long sint64;
typedef short sint16;
typedef char sint8;

typedef bool boolean;


enum UDS_SERVICE : uint8_t {
    DIAGNOSTIC_SESSION_CONTROL_0x10 = 0x10,
    ECU_RESET_0x11 = 0x11,
    CLEAR_DIAGNOSTIC_INFO_0x14 = 0x14,
    READ_DTC_INFO_0x19 = 0x19,
    READ_DID_0x22 = 0x22,
    READ_MEMORY_BY_ADDRESS_0x23 = 0x23,
    READ_SCALING_DID_0x24 = 0x24,
    SECURITY_ACCESS_0x27 = 0x27,
    COMMUNICATION_CONTROL_0x28 = 0x28,
    AUTHENTICATION+0x29 = 0x29,
    READ_DID_PERIODIC_0x2A = 0x2a,
    DYNAMICALLY_DEFINE_DID_0x2C = 0x2c,
    WRITE_DID_0x2E = 0x2e,
    IO_CONTROL_0x2F = 0x2f,
    ROUTINE_CONTROL_0x31 = 0x31,
    REQUEST_DOWNLOAD_0x34 = 0x34,
    REQUEST_UPLOAD_0x35 = 0x35,
    TRANSFER_DATA_0x36 = 0x36,
    REQUEST_TRANSFER_EXIT_0x37 = 0x37,
    REQUEST_FILE_TRANSFER_0x38 = 0x38,
    WRITE_MEMORY_BY_ADDRESS_0x3D = 0x3d,
    TESTER_PRESENT_0x3E = 0x3e,
    ACCESS_TIMING_PARAMS_0x83 = 0x83,
    SECURE_DATA_TRANSMISSION_0x84 = 0x84,
    CONTROL_DTC_SETTINGS_0x85 = 0x85,
    RESPONSE_ON_EVENT_0x86 = 0x86,
    LINK_CONTROL_0x87 = 0x87
};

enum XCP_ERROR : uint8_t
{
    ERR_CMD_SYNC_0x00 = 0x00,
    ERR_CMD_BUSY_0x10 = 0x10,
    ERR_DAQ_ACTIVE_0x11 = 0x11,
    ERR_PGM_ACTIVE_0x12 = 0x12,
    ERR_CMD_UNKNOWN_0x20 = 0x20,
    ERR_CMD_SYNTAX_0x21 = 0x21,
    ERR_OUT_OF_RANGE_0x22 = 0x22,
    ERR_WRITE_PROTECTED_0x23 = 0x23,
    ERR_ACCESS_DENIED_0x24 = 0x24,
    ERR_ACCESS_LOCKED_0x25 = 0x25,
    ERR_PAGE_NOT_VALID_0x26 = 0x26,
    ERR_MODE_NOT_VALID_0x27 = 0x27,
    ERR_SEGMENT_NOT_VALID_0x28 = 0x28,
    ERR_SEQUENCE_0x29 = 0x29,
    ERR_DAQ_CONFIG_0x2A = 0x2A,
    ERR_MEMORY_OVERFLOW_0x30 = 0x30,
    ERR_GENERIC_0x31 = 0x31,
    ERR_VERIFY_0x32 = 0x32,
    ERR_RESOURCE_TEMPORARY_NOT_ACCESSIBLE_0x33 = 0x33,
    ERR_SUBCMD_UNKNOWN_0x34 = 0x34,
    ERR_TIMECORR_STATE_CHANGE_0x35 = 0x35,
    ERR_DBG_0xFC = 0xFC
};

enum UDS_ERROR : uint8_t
{
    GENERAL_REJECT_0x10 = 0x10,
    SERVICE_NOT_SUPPORTED_0x11 = 0x11,
    SUBFUNCTION_NOT_SUPPORTED_0x12 = 0x12,
    INOCRRECT_MESSAGE_LEN_0x13 = 0x13,
    RESPONSE_TOO_LONG_0x14 = 0x14,
    BUSY_0x21 = 0x21,
    CONDITIONS_NOT_CORRECT_0x22 = 0x22,
    REQUEST_SEQUENCE_ERROR_0x24 = 0x24,
    NO_RESPONSE_FROM_SUBNET_0x25 = 0x25,
    FAILURE_PREVENTS_EXECUTION_0x26 = 0x26,
    REQUEST_OUT_OF_RANGE_0x31 = 0x31,
    SECURITY_ACCESS_DENIED_0x33 = 0x33,
    AUTH_FAILURE_0x34 = 0x34,
    INVALID_KEY_0x35 = 0x35,
    EXCEEDED_NUM_OF_ATTEMPTS_0x36 = 0x36,
    REQUIRED_TIME_DELAY_NOT_EXPIRED_0x37 = 0x37,
    SECURE_DATA_TRANS_REQUIRED_0x38 = 0x38,
    SECURE_DATA_TRANS_NOT_ALLOWED_0x39 = 0x39,
    SECURE_DATA_TVERIFYCATION_FAILED_0x3A = 0x3A,
    CERT_VAL_FAILED_INVALID_PERIOD_0x50 = 0x50,
    CERT_VAL_FAILED_INVALID_SIGNATURE_0x51 = 0x51,
    CERT_VAL_FAILED_INVALID_CHAIN_OF_TRUST_0x52 = 0x52,
    CERT_VAL_FAILED_INVALID_TYPE_0x53 = 0x53,
    CERT_VAL_FAILED_INVALID_FORMAT_0x54 = 0x54,
    CERT_VAL_FAILED_INVALID_CONTENT_0x55 = 0x55,
    CERT_VAL_FAILED_INVALID_SCOPE_0x56 = 0x56,
    CERT_VAL_FAILED_INVALID_CERTIFICATE_0x57 = 0x57,
    OWNERSHIP_VERIFICATION_FAILED_0x58 = 0x58,
    CHALLENGE_CALC_FAILED_0x59 = 0x59,
    SETTING_ACCESS_RIGTS_FAILED_0x5A = 0x5A,
    SESSION_KEY_CREATION_FAILED_0x5B = 0x5B,
    CONF_DATA_USAGE_FAILED_0x5C = 0x5C,
    DEAUTH_FAILED_0x5D = 0x5D,
    UPLOAD_DOWNLOAD_NOT_ACCEPTED_0x70 = 0x70,
    TRANSFER_DATA_SUSPENDED_0x71 = 0x71,
    GENERAL_PROGRAMMING_FAILURE_0x72 = 0x72,
    WRONG_BLOCK_SEQ_NUMBER_0x73 = 0x73,
    RESPONSE_PENDING_0x78 = 0x78,
    SUBFUNC_NOT_SUPPORTED_IN_CURRENT_SESSION_0x7E = 0x7E,
    SERVICE_NOT_SUPPORTED_IN_CURRENT_SESSION_0x7F = 0x7F,
    RPM_TOO_HIGH_0x81 = 0x81,
    RPM_TOO_LOW_0x82 = 0x82,
    RENGINE_RUNNING_0x83 = 0x83,
    RENGINE_NOT_RUNNING_0x84 = 0x84,
    RENGINE_RUNTIME_LOW_0x85 = 0x85,
    TEMP_TOO_HIGH_0x86 = 0x86,
    TEMP_TOO_LOW_0x87 = 0x87,
    VEHICLE_SPEED_TOO_HIGH_0x88 = 0x88,
    VEHICLE_SPEED_TOO_LOW_0x89 = 0x89,
    THROTTLE_TOO_HIGH_0x8A = 0x8A,
    THROTTLE_TOO_LOW_0x8B = 0x8B,
    TRANSMISSION_NOT_NEUTRAL_0x8C = 0x8C,
    TRANSMISSION_NOT_IN_GEAR_0x8D = 0x8D,
    BREAK_SWITCH_NOT_CLOSED_0x8F = 0x8F,
    SHIFTER_NOT_IN_PARK_0x90 = 0x90,
    TORQUE_CONVERTER_CLUTCH_LOCKED_0x91 = 0x91,
    VOLTAGE_TOO_HIGH_0x92 = 0x92,
    VOLTAGE_TOO_LOW_0x93 = 0x93,
    RESOURCE_TEMPORARILY_UNAVAILABLE_0x94 = 0x94,
};



struct PduInfoType {
    uint8* SduDataPtr;
    uint8* MetaDataPtr;
    PduLengthType SduLength;
};

enum TPParameterType {
    TP_STMIN = 0x00,
    TP_BS = 0x01,
    TP_BC = 0x02
};

enum BufReq_ReturnType {
    BUFREQ_OK = 0x00,
    BUFREQ_E_NOT_OK = 0x01,
    BUFREQ_E_BUSY = 0x02,
    BUFREQ_E_OVFL = 0x03
};

enum TpDataStateType {
    TP_DATACONF = 0x00,
    TP_DATARETRY = 0x01,
    TP_CONFPENDING = 0x02
};

struct RetryInfoType {
    TpDataStateType TpDataState;
    PduLengthType TxTpDataCnt;
};

enum Std_TransformerClass {
    STD_TRANSFORMER_UNSPECIFIED = 0x00,
    STD_TRANSFORMER_SERIALIZER = 0x01,
    STD_TRANSFORMER_SAFETY = 0x02,
    STD_TRANSFORMER_SECURITY = 0x03,
    STD_TRANSFORMER_CUSTOM = 0xFF
};
enum Std_ReturnType {
    E_OK = 0x0,
    E_NOT_OK = 0x1
};

enum Std_TransformerForwardCode {
    E_OK_FW_CODE = 0x0,
    E_SAFETY_INVALID_REP = 0x01,
    E_SAFETY_INVALID_SEQ = 0x02,
    E_SAFETY_INVALID_CRC = 0x03
};

enum Std_MessageTypeType {
    STD_MESSAGETYPE_REQUEST = 0x0,
    STD_MESSAGETYPE_RESPONSE = 0x1
};

enum Std_MessageResultType {
    STD_MESSAGERESULT_OK = 0x0,
    STD_MESSAGERESULT_ERROR = 0x01
};

struct Std_TransformerForward {
    Std_TransformerForwardCode errorCode;
    Std_TransformerClass transformerClass;
};

typedef Std_ReturnType(*Std_ExtractProtocolHeaderFieldsType)(uint8*,uint32,Std_MessageTypeType*,Std_MessageResultType*);


struct Std_VersionInfoType {
    uint16 vendorID;
    uint16 moduleID;
    uint8 sw_major_version;
    uint8 sw_minor_version;
    uint8 sw_patch_version;
};

struct Std_TransformerError {
    Std_TransformerErrorCode errorCode;
    Std_TransformerClass transformerClass;
};

typedef uint8 NetworkHandleType;

struct TimeStampType {
	uint32 nanoseconds;
	uint32 seconds;
	uint16 secondsHi;
};

typedef unsigned int PLATFORM_MAX_INT;


//====================================================================================================
//[*] Processing ADC Driver (Adc) - ID: 123
struct Adc_ConfigType {
	implementation_specific IMPLEMENATION_SPECIFIC;
};

typedef uint Adc_ChannelType;

typedef uint Adc_GroupType;

typedef int Adc_ValueGroupType;

typedef uint Adc_PrescaleType;

typedef uint Adc_ConversionTimeType;

typedef uint Adc_SamplingTimeType;

typedef uint8 Adc_ResolutionType;

enum Adc_StatusType {
	ADC_IDLE = 0x00,
	ADC_BUSY = 0x01,
	ADC_COMPLETED = 0x02,
	ADC_STREAM_COMPLETED = 0x03
};

enum Adc_TriggerSourceType {
	ADC_TRIGG_SRC_SW = 0x00,
	ADC_TRIGG_SRC_HW = 0x01
};

enum Adc_GroupConvModeType {
	ADC_CONV_MODE_ONESHOT = 0x00,
	ADC_CONV_MODE_CONTINUOUS = 0x01
};

typedef uint8 Adc_GroupPriorityType;

typedef implementation_specific Adc_GroupDefType;
typedef uint Adc_StreamNumSampleType;

enum Adc_StreamBufferModeType {
	ADC_STREAM_BUFFER_LINEAR = 0x00,
	ADC_STREAM_BUFFER_CIRCULAR = 0x01
};

enum Adc_GroupAccessModeType {
	ADC_ACCESS_MODE_SINGLE = 0x00,
	ADC_ACCESS_MODE_STREAMING = 0x01
};

enum Adc_HwTriggerSignalType {
	ADC_HW_TRIG_RISING_EDGE = 0x00,
	ADC_HW_TRIG_FALLING_EDGE = 0x01,
	ADC_HW_TRIG_BOTH_EDGES = 0x02
};

typedef uint Adc_HwTriggerTimerType;

enum Adc_PriorityImplementationType {
	ADC_PRIORITY_NONE = 0x00,
	ADC_PRIORITY_HW = 0x01,
	ADC_PRIORITY_HW_SW = 0x02
};

enum Adc_GroupReplacementType {
	ADC_GROUP_REPL_ABORT_RESTART = 0x00,
	ADC_GROUP_REPL_SUSPEND_RESUME = 0x01
};

enum Adc_ChannelRangeSelectType {
	ADC_RANGE_UNDER_LOW = 0x00,
	ADC_RANGE_BETWEEN = 0x01,
	ADC_RANGE_OVER_HIGH = 0x02,
	ADC_RANGE_ALWAYS = 0x03,
	ADC_RANGE_NOT_UNDER_LOW = 0x04,
	ADC_RANGE_NOT_BETWEEN = 0x05,
	ADC_RANGE_NOT_OVER_HIGH = 0x06
};

enum Adc_ResultAlignmentType {
	ADC_ALIGN_LEFT = 0x00,
	ADC_ALIGN_RIGHT = 0x01
};

enum Adc_PowerStateType {
	ADC_FULL_POWER = 0
};

enum Adc_PowerStateRequestResultType {
	ADC_SERVICE_ACCEPTED = 0,
	ADC_NOT_INIT = 1,
	ADC_SEQUENCE_ERROR = 2,
	ADC_HW_FAILURE = 3,
	ADC_POWER_STATE_NOT_SUPP = 4,
	ADC_TRANS_NOT_POSSIBLE = 5
};

//[*] Extracted 18 items.

//====================================================================================================
//[*] Processing AUTOSAR Run-Time Interface (Arti) - ID: 5

# define ARTI_STOPWATCH_FLAT  0x00u
# define ARTI_STOPWATCH_NESTED  0x01u


//[*] Extracted 2 items.

//====================================================================================================
//[*] Processing BSW Mode Manager (BswM) - ID: 42
struct BswM_ConfigType {
	implementation_specific IMPLEMENATION_SPECIFIC;
};

typedef uint16 BswM_ModeType;

typedef uint16 BswM_UserType;

//[*] Extracted 31 items.

//====================================================================================================
//[*] Processing BSW Scheduler Module (SchM) - ID: 130
//[!] Error trying to retrieve the file at https://www.autosar.org/fileadmin/standards/R23-11/CP/"sinceRel.4.0partofRTE"
//====================================================================================================
//[*] Processing Bulk NvData Manager (BndM) - ID: 23
struct BndM_ConfigType {
	implementation_specific IMPLEMENATION_SPECIFIC;
};

typedef uint16 BndM_BlockIdType;

struct BndM_Block_BlockId_ShortnameType {
	implementation_specific IMPLEMENATION_SPECIFIC;
};

typedef uint8 BndM_ResultType;

//[*] Extracted 13 items.

//====================================================================================================
//[*] Processing Bus Mirroring (Mirror) - ID: 48
struct Mirror_ConfigType {
	implementation_specific IMPLEMENATION_SPECIFIC;
};

//[*] Extracted 28 items.

//====================================================================================================
//[*] Processing CAN Driver (Can) - ID: 80
struct Can_ConfigType {
	implementation_specific IMPLEMENATION_SPECIFIC;
};

typedef uint32 Can_IdType;
struct Can_PduType {
	PduIdType swPduHandle;
	uint8 length;
	Can_IdType id;
	uint8* sdu;
};



typedef uint16 Can_HwHandleType;

struct Can_HwType {
	Can_IdType CanId;
	Can_HwHandleType Hoh;
	uint8 ControllerId;
};

enum Can_ErrorStateType {
	CAN_ERRORSTATE_ACTIVE,
	CAN_ERRORSTATE_PASSIVE,
	CAN_ERRORSTATE_BUSOFF
};

enum Can_ControllerStateType {
	CAN_CS_UNINIT = 0x00,
	CAN_CS_STARTED = 0x01,
	CAN_CS_STOPPED = 0x02,
	CAN_CS_SLEEP = 0x03
};

enum Can_ErrorType {
	CAN_ERROR_BIT_MONITORING1 = 0x01,
	CAN_ERROR_BIT_MONITORING0 = 0x02,
	CAN_ERROR_BIT = 0x03,
	CAN_ERROR_CHECK_ACK_FAILED = 0x04,
	CAN_ERROR_ACK_DELIMITER = 0x05,
	CAN_ERROR_ARBITRATION_LOST = 0x06,
	CAN_ERROR_OVERLOAD = 0x07,
	CAN_ERROR_CHECK_FORM_FAILED = 0x08,
	CAN_ERROR_CHECK_STUFFING_FAILED = 0x09,
	CAN_ERROR_CHECK_CRC_FAILED = 0xA,
	CAN_ERROR_BUS_LOCK = 0xB
};

struct Can_TimeStampType {
	uint32 nanoseconds;
	uint32 seconds;
};

//[*] Extracted 23 items.

//====================================================================================================
//[*] Processing CAN Interface (CanIf) - ID: 60
struct CanIf_ConfigType {
	implementation_specific IMPLEMENATION_SPECIFIC;
};

enum CanIf_PduModeType {
	CANIF_OFFLINE = 0x00,
	CANIF_TX_OFFLINE = 0x01,
	CANIF_TX_OFFLINE_ACTIVE = 0x02,
	CANIF_ONLINE = 0x03
};

enum CanIf_NotifStatusType {
	CANIF_TX_RX_NOTIFICATION,
	CANIF_NO_NOTIFICATION = 0x00
};

//[*] Extracted 43 items.

//====================================================================================================
//[*] Processing CAN Network Management (CanNm) - ID: 31
struct CanNm_ConfigType {
	implementation_specific IMPLEMENATION_SPECIFIC;
};

//[*] Extracted 27 items.

//====================================================================================================
//[*] Processing CAN State Manager (CanSM) - ID: 140
struct CanSM_ConfigType {
	implementation_specific IMPLEMENATION_SPECIFIC;
};

enum CanSM_BswMCurrentStateType {
	CANSM_BSWM_NO_COMMUNICATION,
	CANSM_BSWM_SILENT_COMMUNICATION,
	CANSM_BSWM_FULL_COMMUNICATION,
	CANSM_BSWM_BUS_OFF,
	CANSM_BSWM_CHANGE_BAUDRATE
};

//[*] Extracted 18 items.

//====================================================================================================
//[*] Processing CAN Tranceiver Driver (CanTrcv) - ID: 70
struct CanTrcv_ConfigType {
	implementation_specific IMPLEMENATION_SPECIFIC;
};

enum CanTrcv_PNActivationType {
	PN_ENABLED,
	PN_DISABLED
};

enum CanTrcv_TrcvFlagStateType {
	CANTRCV_FLAG_SET,
	CANTRCV_FLAG_CLEARED
};

enum CanTrcv_TrcvModeType {
    CANTRCV_TRCVMODE_NORMAL = 0x00,
	CANTRCV_TRCVMODE_SLEEP,
	CANTRCV_TRCVMODE_STANDBY

};

enum CanTrcv_TrcvWakeupModeType {
	CANTRCV_WUMODE_ENABLE = 0x00,
	CANTRCV_WUMODE_DISABLE = 0x01,
	CANTRCV_WUMODE_CLEAR = 0x02
};

enum CanTrcv_TrcvWakeupReasonType {
	CANTRCV_WU_ERROR = 0x00,
	CANTRCV_WU_NOT_SUPPORTED = 0x01,
	CANTRCV_WU_BY_BUS = 0x02,
	CANTRCV_WU_INTERNALLY = 0x03,
	CANTRCV_WU_RESET = 0x04,
	CANTRCV_WU_POWER_ON = 0x05,
	CANTRCV_WU_BY_PIN = 0x06,
	CANTRCV_WU_BY_SYSERR = 0x07
};

//[*] Extracted 17 items.

//====================================================================================================
//[*] Processing CAN Transport Layer (CanTp) - ID: 35
struct CanTp_ConfigType {
	implementation_specific IMPLEMENATION_SPECIFIC;
};

//[*] Extracted 11 items.

//====================================================================================================
//[*] Processing CAN XL Driver (CanXL) - ID: 85
struct CanXL_Params {
	uint16 PriorityId;
	uint16 Vcid;
	uint8 SduType;
	uint32 AcceptanceField;
	uint8 Sec;
};

struct CanXL_PduType {
	PduIdType swPduHandle;
	uint16 length;
	uint8* sdu;
	CanXL_Params* XLParams;
};

struct CanXL_HwType {
	CanXL_Params* XLParams;
	uint8 ControllerId;
	Can_HwHandleType Hoh;
};

//[*] Extracted 19 items.

//====================================================================================================
//[*] Processing CAN XL Transceiver Driver (CanXLTrcv) - ID: 72
//[*] Extracted 6 items.

//====================================================================================================
//[*] Processing CellularV2X Driver (CV2x) - ID: 189
struct CV2x_ConfigType {
	implementation_specific IMPLEMENATION_SPECIFIC;
};

enum CV2x_StateType {
	CV2X_STATE_UNINIT = 0x00,
	CV2X_STATE_INIT = 0x01
};

enum CV2x_BufCV2xPC5RxParamIdType {
	CV2X_BUFCV2XPC5RXPID_SRC_LAYER2_ID = 0x00,
	CV2X_BUFCV2XPC5RXPID_DST_LAYER2_ID = 0x01,
	CV2X_BUFCV2XPC5RXPID_PPPP = 0x02,
	CV2X_BUFCV2XPC5RXPID_CBR = 0x03,
	CV2X_BUFCV2XPC5RXPID_MAX_DATA_RATE = 0x04,
	CV2X_BUFCV2XPC5RXPID_TRANSACTION_ID_32 = 0x05
};

enum CV2x_BufCV2xPC5TxParamIdType {
	CV2X_BUFCV2XPC5TXPID_PDCP_SDU_TYPE = 0x00,
	CV2X_BUFCV2XPC5TXPID_SRC_LAYER2_ID = 0x01,
	CV2X_BUFCV2XPC5TXPID_DST_LAYER2_ID = 0x02,
	CV2X_BUFCV2XPC5TXPID_PPPP = 0x03,
	CV2X_BUFCV2XPC5TXPID_PDB = 0x04,
	CV2X_BUFCV2XPC5TXPID_TRAFFIC_PERIOD = 0x05,
	CV2X_BUFCV2XPC5TXPID_SRC_IP_ADDR = 0x06,
	CV2X_BUFCV2XPC5TXPID_TRANSACTION_ID_16 = 0x07
};

enum CV2x_GetChanTxParamIdType {
	CV2X_GETCHTXPID_CBR = 0x00,
	CV2X_GETCHTXPID_TP = 0x01,
	CV2X_GETCHTXPID_SYNC_TYPE = 0x02,
	CV2X_GETCHTXPID_SYNC_STATUS = 0x03
};

//[*] Extracted 13 items.

//====================================================================================================
//[*] Processing Charging Manager (ChrgM) - ID: 215
struct ChrgM_ConfigType {
	implementation_specific IMPLEMENATION_SPECIFIC;
};

typedef string ChrgM_ErrorHandlerType;

typedef string ChrgM_ResponseCodeType;

//[*] Extracted 17 items.



//[*] Extracted 4 items.

//====================================================================================================
//[*] Processing Chinese Vehicle-2-X Message (CnV2xMsg) - ID: 190
typedef uint32 CnV2x_Layer2IdType;
typedef uint8 CnV2x_CbrType;
typedef uint8 CnV2x_PPPPType;

typedef uint8 CnV2x_NetworkProtocolType;

typedef uint8 CnV2x_TrafficPeriodType;

typedef uint32 CnV2x_MaxDataRateType;

typedef uint8 CnV2x_NetTxResultType;

enum CnV2xMsg_RxParamsPresenceType {
	SourceMACAddr_CnV2xMsg = 0x08,
	DestinationLayer2Id_CnV2xMsg = 0x04,
	Cbr_CnV2xMsg = 0x02,
	MaxdataRate_CnV2xMsg = 0x01
};

struct CnV2xMsg_RxParamsType {
	CnV2xMsg_RxParamsPresenceType presence;
	uint8 DsmpVersion;
	uint64 Aid;
	CnV2x_Layer2IdType SourceLayer2Id;
	CnV2x_Layer2IdType DestinationLayer2Id;
	uint8 Priority;
	CnV2x_CbrType Cbr;
	CnV2x_MaxDataRateType MaxDataRate;
};



//[*] Extracted 21 items.

//====================================================================================================
//[*] Processing Chinese Vehicle-2-X Network (CnV2xNet) - ID: 191

enum CnV2xNet_TxParamsPresenceType {
	SourceLayer2Id_CnV2xNet = 0x08,
	DestinationLayer2Id_CnV2xNet = 0x04,
	TrafficPeriod_CnV2xNet = 0x02,
	DsmpHeaderExtension_CnV2xNet = 0x01
};

enum CnV2xNet_RxParamsPresenceType {
	Cbr = 0x02,
	maxDataRate = 0x01
};


struct CnV2xNet_TxParamsType {
	CnV2xNet_TxParamsPresenceType presence;
	uint64 Aid;
	CnV2x_NetworkProtocolType ProtocolType;
	uint8 priority;
	CnV2x_Layer2IdType SourceLayer2Id;
	CnV2x_Layer2IdType DestinationLayer2Id;
	CnV2x_TrafficPeriodType TrafficPeriod;
	uint16 AppLayerIdChangedCount16;
	uint8* DsmpHeaderExtensionPtr;
	uint16 DsmpHeaderExtensionLength;
};


struct CnV2xNet_RxParamsType {
	CnV2xNet_RxParamsPresenceType presence;
	CnV2x_Layer2IdType Sourcelayer2Id;
	CnV2x_Layer2IdType DestinationLayer2Id;
	CnV2x_PPPPType pppp;
	CnV2x_CbrType cbr;
	CnV2x_MaxDataRateType MaxDataRate;
};






//[*] Extracted 9 items.

//====================================================================================================
//[*] Processing Chinese Vehicle-2-X Security (CnV2xSec) - ID: 192
struct CnV2xSec_ConfigType {
	implementation_specific IMPLEMENATION_SPECIFIC;
};

enum CnV2xSec_SecProfileType {
	CNV2XSEC_SECPROF_BSM_SIGNED,
	CNV2XSEC_SECPROF_BSM_SIGNED_DEFLECTED_ENCRYPTED,
	CNV2XSEC_SECPROF_BSM_SIGNED_HIGHDEFLECTED_ENCRYPTED,
	CNV2XSEC_SECPROF_OTHER_SIGNED
};

typedef uint8 CnV2xSec_SecReportType;

enum CnV2xSec_SecReturnType {
	CNV2XSEC_E_OK = 0x00,
	CNV2XSEC_E_NOT_OK = 0x01,
	CNV2XSEC_E_BUF_OVFL = 0x02
};

//[*] Extracted 5 items.

//====================================================================================================
//[*] Processing COM (Com) - ID: 50
enum Com_StatusType {
    COM_UNINIT = 0x00,
	COM_INIT
};

typedef uint16 Com_SignalIdType;

typedef uint16 Com_SignalGroupIdType;

typedef uint16 Com_IpduGroupIdType;

struct Com_ConfigType {
	implementation_specific IMPLEMENATION_SPECIFIC;
};

//[*] Extracted 42 items.

//====================================================================================================
//[*] Processing COM Based Transformer (ComXf) - ID: 175
struct ComXf_ConfigType {
	implementation_specific IMPLEMENATION_SPECIFIC;
};

//[*] Extracted 5 items.

//====================================================================================================
//[*] Processing COM Manager (ComM) - ID: 12
enum Std_ReturnType_ComM {
	E_OK_ComM = 0x00,
	E_NOT_OK_ComM = 0x01,
	COMM_E_MODE_LIMITATION = 0x02,
	COMM_E_MULTIPLE_PNC_ASSIGNED = 0x03,
	COMM_E_NO_PNC_ASSIGNED = 0x04,
	COMM_E_LEARNING_ACTIVE = 0x05
};

typedef uint16 ComM_UserHandleType;

enum ComM_ModeType {
	COMM_NO_COMMUNICATION = 0x00,
	COMM_SILENT_COMMUNICATION = 0x01,
	COMM_FULL_COMMUNICATION = 0x02,
	COMM_FULL_COMMUNICATION_WITH_WAKEUP_REQUEST = 0x03
};

enum ComM_InitStatusType {
	COMM_UNINIT = 0x00,
	COMM_INIT = 0x01
};

enum ComM_PncModeType {
	COMM_PNC_REQUESTED = 0x00,
	COMM_PNC_READY_SLEEP = 0x01,
	COMM_PNC_PREPARE_SLEEP = 0x02,
	COMM_PNC_NO_COMMUNICATION = 0x03,
	COMM_PNC_REQUESTED_WITH_WAKEUP_REQUEST = 0x04
};

typedef uint8 ComM_StateType;

struct ComM_ConfigType {
	implementation_specific IMPLEMENATION_SPECIFIC;
};

//[*] Extracted 39 items.

//====================================================================================PLATFORM_MAX_INT================
//[?] Skipping Complex Drivers
//====================================================================================================
//[*] Processing Core Test (CorTst) - ID: 103
struct CorTst_ConfigType {
	implementation_specific IMPLEMENATION_SPECIFIC;
};

enum CorTst_ResultType {
	CORTST_E_NOT_OK = 0x00,
	CORTST_E_OKAY = 0x01,
	CORTST_E_NOT_TESTED = 0x02
};

typedef PLATFORM_MAX_INT CorTst_CsumSignatureType;

struct CorTst_CsumSignatureBgndType {
	implementation_specific IMPLEMENATION_SPECIFIC;
	PLATFORM_MAX_INT CorTstTestIntervalId;
};

struct CorTst_ErrOkType {
	PLATFORM_MAX_INT CorTstTestIntervalId;
	CorTst_ResultType returnvalue;
};

enum CorTst_StateType {
	CORTST_ABORT = 0x00,
	CORTST_INIT = 0x01,
	CORTST_UNINIT = 0x02,
	CORTST_RUNNING_BGND = 0x03
};

typedef PLATFORM_MAX_INT CorTst_TestIdFgndType;

//[*] Extracted 11 items.

//====================================================================================================
//[*] Processing Crypto Driver (Crypto) - ID: 114
enum Std_ReturnType_Crypto {
	E_OK_Crypto = 0x00,
	E_NOT_OK_Crypto = 0x01
};

struct Crypto_ConfigType {
	implementation_specific IMPLEMENATION_SPECIFIC;
};

//[*] Extracted 24 items.

//====================================================================================================
//[*] Processing Crypto Interface (CryIf) - ID: 112
enum Std_ReturnType_CryIf {
	E_OK_CryIf = 0x00,
	E_NOT_OK_CryIf = 0x01,
	CRYPTO_E_BUSY_CryIf = 0x02,
	CRYPTO_E_ENTROPY_EXHAUSTED_CryIf = 0x04,
	CRYPTO_E_KEY_READ_FAIL_CryIf = 0x06,
	CRYPTO_E_KEY_WRITE_FAIL_CryIf = 0x07,
	CRYPTO_E_KEY_NOT_AVAILABLE_CryIf = 0x08,
	CRYPTO_E_KEY_NOT_VALID_CryIf = 0x09,
	CRYPTO_E_KEY_SIZE_MISMATCH_CryIf = 0x0A,
	CRYPTO_E_JOB_CANCELED_CryIf = 0x0C,
	CRYPTO_E_KEY_EMPTY_CryIf = 0x0D,
	CRYPTO_E_CUSTOM_ERROR_CryIf = 0x0E
};

struct CryIf_ConfigType {
	implementation_specific IMPLEMENATION_SPECIFIC;
};

//[*] Extracted 19 items.

//====================================================================================================
//[*] Processing Crypto Service Manager (Csm) - ID: 110
enum Std_ReturnType_Csm {
	E_OK_Csm = 0x00,
	E_NOT_OK_Csm = 0x01,
	CRYPTO_E_BUSY_Csm = 0x02,
	CRYPTO_E_ENTROPY_EXHAUSTED_Csm = 0x04,
	CRYPTO_E_KEY_READ_FAIL_Csm = 0x06,
	CRYPTO_E_KEY_WRITE_FAIL_Csm = 0x07,
	CRYPTO_E_KEY_NOT_AVAILABLE_Csm = 0x08,
	CRYPTO_E_KEY_NOT_VALID_Csm = 0x09,
	CRYPTO_E_KEY_SIZE_MISMATCH_Csm = 0x0A,
	CRYPTO_E_JOB_CANCELED_Csm = 0x0C,
	CRYPTO_E_KEY_EMPTY_Csm = 0x0D,
	CRYPTO_E_CUSTOM_ERROR_Csm = 0x0E
};

struct Csm_ConfigType {
	implementation_specific IMPLEMENATION_SPECIFIC;
};

enum Crypto_JobStateType {
	CRYPTO_JOBSTATE_IDLE = 0x00,
	CRYPTO_JOBSTATE_ACTIVE = 0x01
};

enum Crypto_OperationModeType {
    CRYPTO_OPERATIONMODE_START = 0x01,
    CRYPTO_OPERATIONMODE_UPDATE = 0x02,

};

enum Crypto_VerifyResultType {
    CRYPTO_E_VER_OK = 0x01,
    CRYPTO_E_VER_NOT_OK = 0x02,
    CRYPTO_OPERATIONMODE_STREAMSTART = 0x03,
    CRYPTO_OPERATIONMODE_FINISH = 0x04,
    CRYPTO_OPERATIONMODE_SINGLECALL = 0x07,
    CRYPTO_OPERATIONMODE_SAVE_CONTEXT = 0x08,
    CRYPTO_OPERATIONMODE_RESTORE_CONTEXT = 0x10
};

enum Crypto_KeyStatusType {
    CRYPTO_KEYSTATUS_INVALID = 0x00,
    CRYPTO_KEYSTATUS_VALID = 0x01,
    CRYPTO_KEYSTATUS_UPDATE_IN_PROGRESS = 0x02
};

typedef Crypto_VerifyResultType* Csm_VerifyResultPtr;

enum Crypto_AlgorithmFamilyType {
	CRYPTO_ALGOFAM_NOT_SET = 0x00,
	CRYPTO_ALGOFAM_SHA1 = 0x01,
	CRYPTO_ALGOFAM_SHA2_224 = 0x02,
	CRYPTO_ALGOFAM_SHA2_256 = 0x03,
	CRYPTO_ALGOFAM_SHA2_384 = 0x04,
	CRYPTO_ALGOFAM_SHA2_512 = 0x05,
	CRYPTO_ALGOFAM_SHA2_512_224 = 0x06,
	CRYPTO_ALGOFAM_SHA2_512_256 = 0x07,
	CRYPTO_ALGOFAM_SHA3_224 = 0x08,
	CRYPTO_ALGOFAM_SHA3_256 = 0x09,
	CRYPTO_ALGOFAM_SHA3_384 = 0x0a,
	CRYPTO_ALGOFAM_SHA3_512 = 0x0b,
	CRYPTO_ALGOFAM_SHAKE128 = 0x0c,
	CRYPTO_ALGOFAM_SHAKE256 = 0x0d,
	CRYPTO_ALGOFAM_RIPEMD160 = 0x0e,
	CRYPTO_ALGOFAM_BLAKE_1_256 = 0x0f,
	CRYPTO_ALGOFAM_BLAKE_1_512 = 0x10,
	CRYPTO_ALGOFAM_BLAKE_2s_256 = 0x11,
	CRYPTO_ALGOFAM_BLAKE_2s_512 = 0x12,
	CRYPTO_ALGOFAM_3DES = 0x13,
	CRYPTO_ALGOFAM_AES = 0x14,
	CRYPTO_ALGOFAM_CHACHA = 0x15,
	CRYPTO_ALGOFAM_RSA = 0x16,
	CRYPTO_ALGOFAM_ED25519 = 0x17,
	CRYPTO_ALGOFAM_BRAINPOOL = 0x18,
	CRYPTO_ALGOFAM_ECCNIST = 0x19,
	CRYPTO_ALGOFAM_RNG = 0x1b,
	CRYPTO_ALGOFAM_SIPHASH = 0x1c,
	CRYPTO_ALGOFAM_ECCANSI = 0x1e,
	CRYPTO_ALGOFAM_ECCSEC = 0x1f,
	CRYPTO_ALGOFAM_DRBG = 0x20,
	CRYPTO_ALGOFAM_FIPS186 = 0x21,
	CRYPTO_ALGOFAM_PADDING_PKCS7 = 0x22,
	CRYPTO_ALGOFAM_PADDING_ONEWITHZEROS = 0x23,
	CRYPTO_ALGOFAM_PBKDF2 = 0x24,
	CRYPTO_ALGOFAM_KDFX963 = 0x25,
	CRYPTO_ALGOFAM_DH = 0x26,
	CRYPTO_ALGOFAM_SM2 = 0x27,
	CRYPTO_ALGOFAM_EEA3 = 0x28,
	CRYPTO_ALGOFAM_SM3 = 0x29,
	CRYPTO_ALGOFAM_EIA3 = 0x2A,
	CRYPTO_ALGOFAM_HKDF = 0x2B,
	CRYPTO_ALGOFAM_ECDSA = 0x2C,
	CRYPTO_ALGOFAM_POLY1305 = 0x2D,
	CRYPTO_ALGOFAM_X25519 = 0x2E,
	CRYPTO_ALGOFAM_ECDH = 0x2F,
	CRYPTO_ALGOFAM_CUSTOM = 0xff
};

enum Crypto_AlgorithmModeType {
	CRYPTO_ALGOMODE_NOT_SET = 0x00,
	CRYPTO_ALGOMODE_ECB = 0x01,
	CRYPTO_ALGOMODE_CBC = 0x02,
	CRYPTO_ALGOMODE_CFB = 0x03,
	CRYPTO_ALGOMODE_OFB = 0x04,
	CRYPTO_ALGOMODE_CTR = 0x05,
	CRYPTO_ALGOMODE_GCM = 0x06,
	CRYPTO_ALGOMODE_XTS = 0x07,
	CRYPTO_ALGOMODE_RSAES_OAEP = 0x08,
	CRYPTO_ALGOMODE_RSAES_PKCS1_v1_5 = 0x09,
	CRYPTO_ALGOMODE_RSASSA_PSS = 0x0a,
	CRYPTO_ALGOMODE_RSASSA_PKCS1_v1_5 = 0x0b,
	CRYPTO_ALGOMODE_8ROUNDS = 0x0c,
	CRYPTO_ALGOMODE_12ROUNDS = 0x0d,
	CRYPTO_ALGOMODE_20ROUNDS = 0x0e,
	CRYPTO_ALGOMODE_HMAC = 0x0f,
	CRYPTO_ALGOMODE_CMAC = 0x10,
	CRYPTO_ALGOMODE_GMAC = 0x11,
	CRYPTO_ALGOMODE_CTRDRBG = 0x12,
	CRYPTO_ALGOMODE_SIPHASH_2_4 = 0x13,
	CRYPTO_ALGOMODE_SIPHASH_4_8 = 0x14,
	CRYPTO_ALGOMODE_PXXXR1 = 0x15,
	CRYPTO_ALGOMODE_AESKEYWRAP = 0x16,
	CRYPTO_ALGOMODE_CUSTOM = 0xff
};

enum Crypto_ProcessingType {
	CRYPTO_PROCESSING_ASYNC = 0x00,
	CRYPTO_PROCESSING_SYNC = 0x01
};


enum Crypto_ServiceInfoType {
	CRYPTO_HASH = 0x00,
	CRYPTO_MACGENERATE = 0x01,
	CRYPTO_MACVERIFY = 0x02,
	CRYPTO_ENCRYPT = 0x03,
	CRYPTO_DECRYPT = 0x04,
	CRYPTO_AEADENCRYPT = 0x05,
	CRYPTO_AEADDECRYPT = 0x06,
	CRYPTO_SIGNATUREGENERATE = 0x07,
	CRYPTO_SIGNATUREVERIFY = 0x08,
	CRYPTO_RANDOMGENERATE = 0x0B,
	CRYPTO_RANDOMSEED = 0x0C,
	CRYPTO_KEYGENERATE = 0x0D,
	CRYPTO_KEYDERIVE = 0x0E,
	CRYPTO_KEYEXCHANGECALCPUBVAL = 0x0F,
	CRYPTO_KEYEXCHANGECALCSECRET = 0x10,
	CRYPTO_KEYSETVALID = 0x13,
	CRYPTO_KEYSETINVALID = 0x14,
	CRYPTO_CUSTOM_SERVICE = 0x15
};



enum Crypto_InputOutputRedirectionConfigType {
	CRYPTO_REDIRECT_CONFIG_PRIMARY_INPUT = 0x01,
	CRYPTO_REDIRECT_CONFIG_SECONDARY_INPUT = 0x02,
	CRYPTO_REDIRECT_CONFIG_TERTIARY_INPUT = 0x04,
	CRYPTO_REDIRECT_CONFIG_PRIMARY_OUTPUT = 0x10,
	CRYPTO_REDIRECT_CONFIG_SECONDARY_OUTPUT = 0x20
};
struct Crypto_JobPrimitiveInputOutputType {
	const uint8* inputPtr;
	uint32 inputLength;
	const uint8* secondaryInputPtr;
	uint32 secondaryInputLength;
	const uint8* tertiaryInputPtr;
	uint32 tertiaryInputLength;
	uint8* outputPtr;
	uint32* outputLengthPtr;
	uint8* secondaryOutputPtr;
	uint32* secondaryOutputLengthPtr;
	Crypto_VerifyResultType* verifyPtr;
	Crypto_OperationModeType mode;
	uint32 cryIfKeyId;
	uint32 targetCryIfKeyId;
};
struct Crypto_JobRedirectionInfoType {
	uint8 redirectionConfig;
	uint32 inputKeyId;
	uint32 inputKeyElementId;
	uint32 secondaryInputKeyId;
	uint32 secondaryInputKeyElementId;
	uint32 tertiaryInputKeyId;
	uint32 tertiaryInputKeyElementId;
	uint32 outputKeyId;
	uint32 outputKeyElementId;
	uint32 secondaryOutputKeyId;
	uint32 secondaryOutputKeyElementId;
};


struct Crypto_AlgorithmInfoType {
	Crypto_AlgorithmFamilyType family;
	Crypto_AlgorithmFamilyType secondaryFamily;
	uint32 keyLength;
	Crypto_AlgorithmModeType mode;
};

struct Crypto_PrimitiveInfoType {
	const Crypto_ServiceInfoType service;
	const Crypto_AlgorithmInfoType algorithm;
};



struct Crypto_JobPrimitiveInfoType {
	uint32 callbackId;
	const Crypto_PrimitiveInfoType* primitiveInfo;
	uint32 cryIfKeyId;
	Crypto_ProcessingType processingType;
};

struct Crypto_JobType {
	uint32 jobId;
	Crypto_JobStateType jobState;
	Crypto_JobPrimitiveInputOutputType jobPrimitiveInputOutput;
	const Crypto_JobPrimitiveInfoType* jobPrimitiveInfo;
	Crypto_JobRedirectionInfoType* jobRedirectionInfoRef;
	uint32 cryptoKeyId;
	uint32 targetCryptoKeyId;
	const uint32 jobPriority;
};











//[*] Extracted 39 items.

//====================================================================================================
//[*] Processing Data DistributionService (Dds) - ID: 47
struct Dds_ConfigType {
	implementation_specific IMPLEMENATION_SPECIFIC;
};

//[*] Extracted 8 items.

//====================================================================================================
//[*] Processing Default Error Tracer (Det) - ID: 15
struct Det_ConfigType {
	implementation_specific IMPLEMENATION_SPECIFIC;
};

//[*] Extracted 9 items.

//====================================================================================================
//[*] Processing Diagnostic CommunicationManager (Dcm) - ID: 53
typedef uint8 Dcm_StatusType;

typedef uint8 Dcm_CommunicationModeType;

typedef uint8 Dcm_NegativeResponseCodeType;

typedef uint8 Dcm_SecLevelType;

enum Dcm_ConfirmationStatusType {
	DCM_RES_POS_OK = 0x0,
	DCM_RES_POS_NOT_OK = 0x1,
	DCM_RES_NEG_OK = 0x2,
	DCM_RES_NEG_NOT_OK = 0x3
};

enum Dcm_OpStatusType {
	DCM_INITIAL = 0x0,
	DCM_PENDING = 0x1,
	DCM_CANCEL = 0x2,
	DCM_FORCE_RCRRP_OK = 0x3
};

enum Dcm_SesCtrlType {
	Dcm_SesCtrlType = 0x01,
	DCM_PROGRAMMING_SESSION = 0x02,
	DCM_EXTENDED_DIAGNOSTIC_SESSION = 0x03,
	DCM_SAFETY_SYSTEM_DIAGNOSTIC_SESSION = 0x04
};

enum Dcm_ProtocolType {
	DCM_OBD_ON_CAN,
	DCM_OBD_ON_FLEXRAY,
	DCM_OBD_ON_IP,
	DCM_UDS_ON_CAN,
	DCM_UDS_ON_FLEXRAY,
	DCM_UDS_ON_IP,
	DCM_ROE_ON_CAN,
	DCM_ROE_ON_FLEXRAY,
	DCM_ROE_ON_IP,
	DCM_PERIODICTRANS_ON_CAN,
	DCM_PERIODICTRANS_ON_FLEXRAY,
	DCM_PERIODICTRANS_ON_IP,
	DCM_NO_ACTIVE_PROTOCOL,
	DCM_UDS_ON_LIN
};

typedef uint8 Dcm_NegativeResponseCodeType;

struct Dcm_ConfigType {
	implementation_specific IMPLEMENATION_SPECIFIC;
};

typedef uint8 Dcm_ReturnReadMemoryType;

typedef uint8 Dcm_RequestDataArrayType[];

typedef uint8 Dcm_EcuStartModeType;


enum Dcm_ReturnWriteMemoryType {
	DCM_WRITE_OK,
	DCM_WRITE_PENDING,
	DCM_WRITE_FAILED,
	DCM_WRITE_FORCE_RCRRP
};

struct Dcm_ProgConditionsType {
	uint16 ConnectionId;
	uint16 TesterAddress;
	uint8 Sid;
	uint8 SubFncId;
	boolean ReprogramingRequest;
	boolean ApplUpdated;
	boolean ResponseRequired;
};

typedef uint8 Dcm_MsgItemType;

typedef uint32 Dcm_MsgLenType;

struct Dcm_MsgAddInfoType {
	uint8 reqType;
	uint8 suppressPosResponse;
};

typedef uint8 Dcm_IdContextType;

typedef Dcm_MsgItemType* Dcm_MsgType;

struct Dcm_MsgContextType {
	Dcm_MsgType reqData;
	Dcm_MsgLenType reqDataLen;
	Dcm_MsgType resData;
	Dcm_MsgLenType resDataLen;
	Dcm_MsgAddInfoType msgAddInfo;
	Dcm_MsgLenType resMaxDataLen;
	Dcm_IdContextType idContext;
	PduIdType dcmRxPduId;
};

typedef uint8 Dcm_ExtendedOpStatusType;

//[*] Extracted 78 items.

//====================================================================================================
//[*] Processing Diagnostic Event Manager (Dem) - ID: 54
typedef uint16 Dem_ComponentIdType;

struct Dem_ConfigType {
	implementation_specific IMPLEMENATION_SPECIFIC;
};

typedef uint8 Dem_DTCKindType;

typedef uint8 Dem_DTCRequestType;

typedef uint8 Dem_DTCTranslationFormatType;

typedef uint8 Dem_UdsStatusByteType;

typedef uint8 Dem_PID4DvalueType[2];

typedef uint8 Dem_PID4EvalueType[2];

typedef uint8 Dem_PID31valueType[2];

typedef uint8 Dem_PID21valueType[2];

typedef uint8 Dem_MonitorStatusType;

typedef uint32 Dem_MonitorDataType;

enum Dem_IumprDenomCondStatusType {
	DEM_IUMPR_DEN_STATUS_NOT_REACHED,
	DEM_IUMPR_DEN_STATUS_REACHED,
	DEM_IUMPR_DEN_STATUS_INHIBITED
};

typedef uint8 Dem_IumprDenomCondIdType;

enum Dem_DTRControlType {
	DEM_DTR_CTL_NORMAL,
	DEM_DTR_CTL_NO_MAX,
	DEM_DTR_CTL_NO_MIN,
	DEM_DTR_CTL_RESET,
	DEM_DTR_CTL_INVISIBLE
};

typedef uint16 Dem_EventIdType;

typedef uint8 Dem_DebounceResetStatusType;

typedef uint8 Dem_DebouncingStateType;

typedef uint16 Dem_DTCOriginType;

enum Dem_EventStatusType {
	DEM_EVENT_STATUS_PASSED,
	DEM_EVENT_STATUS_FAILED,
	DEM_EVENT_STATUS_PREPASSED,
	DEM_EVENT_STATUS_PREFAILED,
	DEM_EVENT_STATUS_FDC_THRESHOLD_REACHED
};

enum Dem_DTCFormatType {
	DEM_DTC_FORMAT_OBD,
	DEM_DTC_FORMAT_UDS,
	DEM_DTC_FORMAT_J1939,
	DEM_DTC_FORMAT_OBD_3BYTE
};

enum Dem_IndicatorStatusType {
	DEM_INDICATOR_OFF,
	DEM_INDICATOR_CONTINUOUS,
	DEM_INDICATOR_BLINKING,
	DEM_INDICATOR_BLINK_CONT,
	DEM_INDICATOR_SLOW_FLASH,
	DEM_INDICATOR_FAST_FLASH,
	DEM_INDICATOR_ON_DEMAND,
	DEM_INDICATOR_SHORT
};

typedef uint16 Dem_RatioIdType;


enum Dem_DTCSeverityType {
	DEM_SEVERITY_NO_SEVERITY = 0x00,
	DEM_SEVERITY_WWHOBD_CLASS_NO_CLASS = 0x01,
	DEM_SEVERITY_WWHOBD_CLASS_A = 0x02,
	DEM_SEVERITY_WWHOBD_CLASS_B1 = 0x04,
	DEM_SEVERITY_WWHOBD_CLASS_B2 = 0x08,
	DEM_SEVERITY_WWHOBD_CLASS_C = 0x10,
	DEM_SEVERITY_MAINTENANCE_ONLY = 0x20,
	DEM_SEVERITY_CHECK_AT_NEXT_HALT = 0x40,
	DEM_SEVERITY_CHECK_IMMEDIATELY = 0x80
};

typedef uint8 Dem_J1939DcmDTCStatusFilterType;

typedef uint8 Dem_J1939DcmSetClearFilterType;

typedef uint8 Dem_J1939DcmSetFreezeFrameFilterType;

struct Dem_J1939DcmLampStatusType {
	uint8 LampStatus;
	uint8 FlashLampStatus;
};

struct Dem_J1939DcmDiagnosticReadiness1Type {
	uint8 ActiveTroubleCodes;
	uint8 PreviouslyActiveDiagnosticTroubleCodes;
	uint8 OBDCompliance;
	uint8 ContinuouslyMonitoredSystemsSupport_Status;
	uint8 NonContinuouslyMonitoredSystemsSupport5;
	uint8 NonContinuouslyMonitoredSystemsSupport6;
	uint8 NonContinuouslyMonitoredSystemsStatus7;
	uint8 NonContinuouslyMonitoredSystemsStatus8;
};

struct Dem_J1939DcmDiagnosticReadiness2Type {
	uint16 DistanceTraveledWhileMILisActivated;
	uint16 DistanceSinceDTCsCleared;
	uint16 MinutesRunbyEngineWhileMILisActivated;
	uint16 TimeSinceDiagnosticTroubleCodesCleared;
};

struct Dem_J1939DcmDiagnosticReadiness3Type {
	uint16 TimeSinceEngineStart;
	uint8 NumberofWarmupsSinceDTCsCleared;
	uint8 ContinuouslyMonitoredSystemsEnableCompletedStatus;
	uint8 NonContinuouslyMonitoredSystemsEnableStatus5;
	uint8 NonContinuouslyMonitoredSystemsEnableStatus6;
	uint8 NonContinuouslyMonitoredSystems7;
	uint8 NonContinuouslyMonitoredSystems8;
};

typedef uint8 Dem_EventOBDReadinessGroupType;

//[*] Extracted 112 items.

//====================================================================================================
//[*] Processing Diagnostic Log and Trace (Dlt) - ID: 55
struct Dlt_ConfigType {
	implementation_specific IMPLEMENATION_SPECIFIC;
};

enum Dlt_MessageType {
	DLT_TYPE_LOG = 0x00,
	DLT_TYPE_APP_TRACE = 0x01,
	DLT_TYPE_NW_TRACE = 0x02,
	DLT_TYPE_CONTROL = 0x03
};

typedef uint8 Dlt_MessageIDType[4];

enum Dlt_MessageNetworkTraceInfoType {
	DLT_NW_TRACE_IPC = 0x01,
	DLT_NW_TRACE_CAN = 0x02,
	DLT_NW_TRACE_FLEXRAY = 0x03,
	DLT_NW_TRACE_MOST = 0x04,
	DLT_NW_TRACE_ETHERNET = 0x05,
	DLT_NW_TRACE_SOMEIP = 0x06
};

//[*] Extracted 33 items.

//====================================================================================================
//[*] Processing Diagnostic over IP (DoIP) - ID: 173
typedef uint8 DoIP_FurtherActionByteType;

struct DoIP_ConfigType {
	implementation_specific IMPLEMENATION_SPECIFIC;
};

//[*] Extracted 19 items.

//====================================================================================================
//[*] Processing DIO Driver (Dio) - ID: 120
typedef uint Dio_ChannelType;

typedef uint Dio_PortType;

struct Dio_ChannelGroupType {
	uint32 mask;
	uint8 offset;
	Dio_PortType port;
};

typedef uint8 Dio_LevelType;

typedef uint Dio_PortLevelType;

//[*] Extracted 9 items.

//====================================================================================================
//[*] Processing E2E Transformer (E2EXf) - ID: 176
struct E2EXf_ConfigType {
	implementation_specific IMPLEMENATION_SPECIFIC;
};

struct E2EXf_CSTransactionHandleType {
	uint32 e2eCounter;
	uint32 e2eSourceId;
};

//[*] Extracted 5 items.

//====================================================================================================
//[*] Processing ECU State Manager (EcuM) - ID: 10
struct EcuM_ConfigType {
	implementation_specific IMPLEMENATION_SPECIFIC;
};

typedef uint8 EcuM_RunStatusType;

typedef uint32 EcuM_WakeupSourceType;

typedef uint8 EcuM_WakeupStatusType;

typedef uint8 EcuM_ResetType;

typedef uint8 EcuM_StateType;

typedef uint16 EcuM_ShutdownModeType;

typedef uint8 EcuM_ShutdownTargetType;

//[*] Extracted 52 items.

//====================================================================================================
//[*] Processing EEPROM Abstraction (Ea) - ID: 40
struct Ea_ConfigType {
	implementation_specific IMPLEMENATION_SPECIFIC;
};

//[*] Extracted 11 items.

//====================================================================================================
//[*] Processing EEPROM Driver (Eep) - ID: 90
struct Eep_ConfigType {
	implementation_specific IMPLEMENATION_SPECIFIC;
};

typedef uint Eep_AddressType;

typedef uint Eep_LengthType;

//[*] Extracted 11 items.

//====================================================================================================
//[*] Processing Ethernet Driver (Eth) - ID: 88
struct Eth_ConfigType {
	implementation_specific IMPLEMENATION_SPECIFIC;
};

enum Eth_ModeType {
	ETH_MODE_DOWN = 0x00,
	ETH_MODE_ACTIVE = 0x01,
	ETH_MODE_ACTIVE_WITH_WAKEUP_REQUEST = 0x02,
	ETH_MODE_ACTIVE_TX_OFFLINE = 0x03
};

enum Eth_StateType {
	ETH_STATE_UNINIT = 0x00,
	ETH_STATE_INIT = 0x01
};

typedef uint16 Eth_FrameType;

typedef uint16 Eth_DataType;

typedef uint32 Eth_BufIdxType;

typedef uint8 Eth_RateDeviationStatusType;

enum Eth_RxStatusType {
	ETH_RECEIVED = 0x00,
	ETH_NOT_RECEIVED = 0x01,
	ETH_RECEIVED_MORE_DATA_AVAILABLE = 0x02
};

enum Eth_FilterActionType {
	ETH_ADD_TO_FILTER = 0x00,
	ETH_REMOVE_FROM_FILTER = 0x01
};

enum Eth_TimeStampQualType {
	ETH_VALID = 0,
	ETH_INVALID = 1,
	ETH_UNCERTAIN = 2
};

struct Eth_TimeStampType {
	uint32 nanoseconds;
	uint32 seconds;
	uint16 secondsHi;
};

struct Eth_TimeIntDiffType {
	Eth_TimeStampType diff;
	boolean sign;
};

struct Eth_RateRatioType {
	Eth_TimeIntDiffType IngressTimeStampDelta;
	Eth_TimeIntDiffType OriginTimeStampDelta;
};

struct Eth_MacVlanType {
	uint8 MacAddr[6];
	uint16 VlanId;
	uint32 SwitchPort;
};

struct Eth_CounterType {
	uint32 DropPktBufOverrun;
	uint32 DropPktCrc;
	uint32 UndersizePkt;
	uint32 OversizePkt;
	uint32 AlgnmtErr;
	uint32 SqeTestErr;
	uint32 DiscInbdPkt;
	uint32 ErrInbdPkt;
	uint32 DiscOtbdPkt;
	uint32 ErrOtbdPkt;
	uint32 SnglCollPkt;
	uint32 MultCollPkt;
	uint32 DfrdPkt;
	uint32 LatCollPkt;
	uint32 HwDepCtr0;
	uint32 HwDepCtr1;
	uint32 HwDepCtr2;
	uint32 HwDepCtr3;
};

struct Eth_RxStatsType {
	uint32 RxStatsDropEvents;
	uint32 RxStatsOctets;
	uint32 RxStatsPkts;
	uint32 RxStatsBroadcastPkts;
	uint32 RxStatsMulticastPkts;
	uint32 RxStatsCrcAlignErrors;
	uint32 RxStatsUndersizePkts;
	uint32 RxStatsOversizePkts;
	uint32 RxStatsFragments;
	uint32 RxStatsJabbers;
	uint32 RxStatsCollisions;
	uint32 RxStatsPkts64Octets;
	uint32 RxStatsPkts65to127Octets;
	uint32 RxStatsPkts128to255Octets;
	uint32 RxStatsPkts256to511Octets;
	uint32 RxStatsPkts512to1023Octets;
	uint32 RxStatsPkts1024to1518Octets;
	uint32 RxUnicastFrames;
};

struct Eth_TxStatsType {
	uint32 TxNumberOfOctets;
	uint32 TxNUcastPkts;
	uint32 TxUniCastPkts;
};

struct Eth_TxErrorCounterValuesType {
	uint32 TxDroppedNoErrorPkts;
	uint32 TxDroppedErrorPkts;
	uint32 TxDeferredTrans;
	uint32 TxSingleCollision;
	uint32 TxMultipleCollision;
	uint32 TxLateCollision;
	uint32 TxExcessiveCollison;
};

struct Eth_SpiStatusType {
	uint32 SpiStatusRegister;
	boolean Sync;
	uint8 BufferStatusTxCredit;
	uint8 BufferStatusRxCredit;
};

struct Eth_RateDeviationType {
	sint32 rateDeviationValue;
	Eth_RateDeviationStatusType rateDeviationStatus;
};



//[*] Extracted 30 items.

//====================================================================================================
//[*] Processing Ethernet Interface (EthIf) - ID: 65
struct EthIf_ConfigType {
	implementation_specific IMPLEMENATION_SPECIFIC;
};

typedef uint8 EthIf_SwitchPortGroupIdxType;

typedef uint8 EthIf_MeasurementIdxType;

struct EthIf_SignalQualityResultType {
	uint32 HighestSignalQuality;
	uint32 LowestSignalQuality;
	uint32 ActualSignalQuality;
};

//[*] Extracted 134 items.

//====================================================================================================
//[*] Processing Ethernet State Manager (EthSM) - ID: 143
enum EthSM_NetworkModeStateType {
	ETHSM_STATE_OFFLINE,
	ETHSM_STATE_WAIT_TRCVLINK,
	ETHSM_STATE_WAIT_ONLINE,
	ETHSM_STATE_ONLINE,
	ETHSM_STATE_ONHOLD,
	ETHSM_STATE_WAIT_OFFLINE
};

//[*] Extracted 9 items.

//====================================================================================================
//[*] Processing Ethernet Switch Driver (EthSwt) - ID: 89
enum EthSwt_StateType {
	ETHSWT_STATE_UNINIT = 0x00,
	ETHSWT_STATE_INIT = 0x01,
	ETHSWT_STATE_PORTINIT_COMPLETED = 0x02,
	ETHSWT_STATE_ACTIVE = 0x03
};

struct EthSwt_ConfigType {
	implementation_specific IMPLEMENATION_SPECIFIC;
};

enum EthSwt_MacLearningType {
	ETHSWT_MACLEARNING_HWDISABLED,
	ETHSWT_MACLEARNING_HWENABLED,
	ETHSWT_MACLEARNING_SWENABLED
};

struct EthSwt_MgmtInfoType {
	uint8 SwitchIdx;
	uint8 SwitchPortIdx;
};

struct EthSwt_PortMirrorCfgType {
	uint8 srcMacAddrFilter[6];
	uint8 dstMacAddrFilter[6];
	uint16 VlanIdFilter;
	uint8 MirroringPacketDivider;
	uint8 MirroringMode;
	uint32 TrafficDirectionIngressBitMask;
	uint32 TrafficDirectionEgressBitMask;
	uint8 CapturePortIdx;
	uint16 ReTaggingVlanId;
	uint16 DoubleTaggingVlanId;
};

enum EthSwt_PortMirrorStateType {
	PORT_MIRRORING_DISABLED = 0x00,
	PORT_MIRRORING_ENABLED = 0x01
};

enum EthSwt_MgmtOwner {
	ETHSWT_MGMT_OBJ_UNUSED = 0x00,
	ETHSWT_MGMT_OBJ_OWNED_BY_ETHSWT = 0x01,
	ETHSWT_MGMT_OBJ_OWNED_BY_UPPER_LAYER = 0x02
};

struct EthSwt_MgmtObjectValidType {
	Std_ReturnType IngressTimestampValid;
	Std_ReturnType EgressTimestampValid;
	Std_ReturnType MgmtInfoValid;
};

struct EthSwt_MgmtObjectType {
	EthSwt_MgmtObjectValidType Validation;
	TimeStampType IngressTimestamp;
	TimeStampType EgressTimestamp;
	EthSwt_MgmtInfoType MgmtInfo;
	EthSwt_MgmtOwner Ownership;
};



//[*] Extracted 80 items.

//====================================================================================================
//[*] Processing Ethernet Transceiver Driver (EthTrcv) - ID: 73
struct EthTrcv_ConfigType {
	implementation_specific IMPLEMENATION_SPECIFIC;
};

enum EthTrcv_LinkStateType {
	ETHTRCV_LINK_STATE_DOWN = 0x00,
	ETHTRCV_LINK_STATE_ACTIVE = 0x01
};

enum EthTrcv_StateType {
	ETHTRCV_STATE_UNINIT = 0x00,
	ETHTRCV_STATE_INIT = 0x01
};

enum EthTrcv_BaudRateType {
	ETHTRCV_BAUD_RATE_10MBIT = 0x00,
	ETHTRCV_BAUD_RATE_100MBIT = 0x01,
	ETHTRCV_BAUD_RATE_1000MBIT = 0x02,
	ETHTRCV_BAUD_RATE_2500MBIT = 0x03
};

enum EthTrcv_DuplexModeType {
	ETHTRCV_DUPLEX_MODE_HALF = 0x00,
	ETHTRCV_DUPLEX_MODE_FULL = 0x01
};

enum EthTrcv_WakeupReasonType {
	ETHTRCV_WUR_NONE = 0x00,
	ETHTRCV_WUR_GENERAL = 0x01,
	ETHTRCV_WUR_INTERNAL = 0x03,
	ETHTRCV_WUR_RESET = 0x04,
	ETHTRCV_WUR_POWER_ON = 0x05,
	ETHTRCV_WUR_PIN = 0x06,
	ETHTRCV_WUR_SYSERR = 0x07,
	ETHTRCV_WUR_WODL_WUP = 0x08,
	ETHTRCV_WUR_WODL_WUR = 0x09,
	ETHTRCV_WUR_TRANSFER = 0xA
};

enum EthTrcv_PhyTestModeType {
	ETHTRCV_PHYTESTMODE_NONE = 0x00,
	ETHTRCV_PHYTESTMODE_1 = 0x01,
	ETHTRCV_PHYTESTMODE_2 = 0x02,
	ETHTRCV_PHYTESTMODE_3 = 0x03,
	ETHTRCV_PHYTESTMODE_4 = 0x04,
	ETHTRCV_PHYTESTMODE_5 = 0x05
};

enum EthTrcv_PhyLoopbackModeType {
	ETHTRCV_PHYLOOPBACK_NONE = 0x00,
	ETHTRCV_PHYLOOPBACK_INTERNAL = 0x01,
	ETHTRCV_PHYLOOPBACK_EXTERNAL = 0x02,
	ETHTRCV_PHYLOOPBACK_REMOTE = 0x03
};

enum EthTrcv_PhyTxModeType {
	ETHTRCV_PHYTXMODE_NORMAL = 0x00,
	ETHTRCV_PHYTXMODE_TX_OFF = 0x01,
	ETHTRCV_PHYTXMODE_SCRAMBLER_OFF = 0x02
};

enum EthTrcv_CableDiagResultType {
	ETHTRCV_CABLEDIAG_OK = 0x00,
	ETHTRCV_CABLEDIAG_ERROR = 0x01,
	ETHTRCV_CABLEDIAG_SHORT = 0x02,
	ETHTRCV_CABLEDIAG_OPEN = 0x03,
	ETHTRCV_CABLEDIAG_PENDING = 0x04,
	ETHTRCV_CABLEDIAG_WRONG_POLARITY = 0x05
};

enum EthTrcv_MacMethodType {
	ETHTRCV_MAC_TYPE_CSMA_CD = 0x00,
	ETHTRCV_MAC_TYPE_PLCA = 0x01
};

//[*] Extracted 38 items.

//====================================================================================================
//[*] Processing Firewall (Fw) - ID: 111
struct Fw_ConfigType {
	implementation_specific IMPLEMENATION_SPECIFIC;
};

typedef uint8 Fw_InspectionResultType;

//[*] Extracted 7 items.

//====================================================================================================
//[*] Processing Flash Driver (Fls) - ID: 92
struct Fls_ConfigType {
	implementation_specific IMPLEMENATION_SPECIFIC;
};

typedef uint Fls_AddressType;

typedef uint Fls_LengthType;

//[*] Extracted 12 items.

//====================================================================================================
//[*] Processing Flash EEPROM Emulation (Fee) - ID: 21
struct Fee_ConfigType {
	implementation_specific IMPLEMENATION_SPECIFIC;
};

//[*] Extracted 11 items.

//====================================================================================================
//[*] Processing Flash Test (FlsTst) - ID: 104
struct FlsTst_ConfigType {
	implementation_specific IMPLEMENATION_SPECIFIC;
};

enum FlsTst_StateType {
	FLSTST_UNINIT = 0x00,
	FLSTST_INIT = 0x01,
	FLSTST_RUNNING = 0x02,
	FLSTST_ABORTED = 0x03,
	FLSTST_SUSPENDED = 0x04
};

enum FlsTst_TestResultType {
	FLSTST_RESULT_NOT_TESTED = 0x00,
	FLSTST_RESULT_OK = 0x01,
	FLSTST_RESULT_NOT_OK = 0x02
};

enum FlsTst_TestResultFgndType {
	FLSTST_NOT_TESTED = 0x00,
	FLSTST_OK = 0x01,
	FLSTST_NOT_OK = 0x02
};

struct FlsTst_TestResultBgndType {
	uint32 FlsTstTestIntervalIdEndValue;
	FlsTst_TestResultType result;
};

typedef uint16 FlsTst_BlockIdFgndType;

struct FlsTst_ErrorDetailsType {
	implementation_specific IMPLEMENATION_SPECIFIC;
};

struct FlsTst_TestSignatureFgndType {
	implementation_specific IMPLEMENATION_SPECIFIC;
};

struct FlsTst_TestSignatureBgndType {
	uint32 FlsTstTestIntervalIdEndValue;
	uint32 Implementationspecific;
};



//[*] Extracted 16 items.

//====================================================================================================
//[*] Processing FlexRay AUTOSAR TransportLayer (FrArTp) - ID: 38
struct FrArTp_ConfigType {
	implementation_specific IMPLEMENATION_SPECIFIC;
};

//[*] Extracted 11 items.

//====================================================================================================
//[*] Processing FlexRay Driver (Fr) - ID: 81
struct Fr_ConfigType {
	implementation_specific IMPLEMENATION_SPECIFIC;
};

enum Fr_POCStateType {
	FR_POCSTATE_CONFIG = 0x00,
	FR_POCSTATE_DEFAULT_CONFIG = 0x01,
	FR_POCSTATE_HALT = 0x02,
	FR_POCSTATE_NORMAL_ACTIVE = 0x03,
	FR_POCSTATE_NORMAL_PASSIVE = 0x04,
	FR_POCSTATE_READY = 0x05,
	FR_POCSTATE_STARTUP = 0x06,
	FR_POCSTATE_WAKEUP = 0x07
};

enum Fr_SlotModeType {
	FR_SLOTMODE_KEYSLOT = 0x00,
	FR_SLOTMODE_ALL_PENDING = 0x01,
	FR_SLOTMODE_ALL = 0x02
};

enum Fr_ErrorModeType {
	FR_ERRORMODE_ACTIVE = 0x00,
	FR_ERRORMODE_PASSIVE = 0x01,
	FR_ERRORMODE_COMM_HALT = 0x02
};

enum Fr_WakeupStatusType {
	FR_WAKEUP_UNDEFINED = 0x00,
	FR_WAKEUP_RECEIVED_HEADER = 0x01,
	FR_WAKEUP_RECEIVED_WUP = 0x02,
	FR_WAKEUP_COLLISION_HEADER = 0x03,
	FR_WAKEUP_COLLISION_WUP = 0x04,
	FR_WAKEUP_COLLISION_UNKNOWN = 0x05,
	FR_WAKEUP_TRANSMITTED = 0x06
};

enum Fr_StartupStateType {
	FR_STARTUP_UNDEFINED = 0x00,
	FR_STARTUP_COLDSTART_LISTEN = 0x01,
	FR_STARTUP_INTEGRATION_COLDSTART_CHECK = 0x02,
	FR_STARTUP_COLDSTART_JOIN = 0x03,
	FR_STARTUP_COLDSTART_COLLISION_RESOLUTION = 0x04,
	FR_STARTUP_COLDSTART_CONSISTENCY_CHECK = 0x05,
	FR_STARTUP_INTEGRATION_LISTEN = 0x06,
	FR_STARTUP_INITIALIZE_SCHEDULE = 0x07,
	FR_STARTUP_INTEGRATION_CONSISTENCY_CHECK = 0x08,
	FR_STARTUP_COLDSTART_GAP = 0x09,
	FR_STARTUP_EXTERNAL_STARTUP = 0x0a
};

struct Fr_POCStatusType {
	boolean CHIHaltRequest;
	boolean ColdstartNoise;
	Fr_ErrorModeType ErrorMode;
	boolean Freeze;
	Fr_SlotModeType SlotMode;
	Fr_StartupStateType StartupState;
	Fr_POCStateType State;
	Fr_WakeupStatusType WakeupStatus;
	boolean CHIReadyRequest;
};

enum Fr_TxLPduStatusType {
	FR_TRANSMITTED = 0x00,
	FR_TRANSMITTED_CONFLICT = 0x01,
	FR_NOT_TRANSMITTED = 0x02
};

enum Fr_RxLPduStatusType {
	FR_RECEIVED = 0x00,
	FR_NOT_RECEIVED = 0x01,
	FR_RECEIVED_MORE_DATA_AVAILABLE = 0x02
};

enum Fr_ChannelType {
	FR_CHANNEL_A = 0x01,
	FR_CHANNEL_B = 0x02,
	FR_CHANNEL_AB = 0x03
};

struct Fr_SlotAssignmentType {
	uint8 Cycle;
	uint16 SlotId;
	Fr_ChannelType channelId;
};

//[*] Extracted 32 items.

//====================================================================================================
//[*] Processing FlexRay Interface (FrIf) - ID: 61
struct FrIf_ConfigType {
	implementation_specific IMPLEMENATION_SPECIFIC;
};

enum FrIf_StateType {
	FRIF_STATE_OFFLINE,
	FRIF_STATE_ONLINE
};

enum FrIf_StateTransitionType {
	FRIF_GOTO_OFFLINE,
	FRIF_GOTO_ONLINE
};

//[*] Extracted 45 items.

//====================================================================================================
//[*] Processing FlexRay ISO Transport Layer (FrTp) - ID: 36
struct FrTp_ConfigType {
	implementation_specific IMPLEMENATION_SPECIFIC;
};

//[*] Extracted 11 items.

//====================================================================================================
//[*] Processing FlexRay Network Management (FrNm) - ID: 32
struct FrNm_ConfigType {
	implementation_specific IMPLEMENATION_SPECIFIC;
};

//[*] Extracted 26 items.

//====================================================================================================
//[*] Processing FlexRay State Manager (FrSM) - ID: 142
struct FrSM_ConfigType {
	implementation_specific IMPLEMENATION_SPECIFIC;
};

enum FrSM_BswM_StateType {
	FRSM_BSWM_READY_ECU_PASSIVE = 0x01,
	FRSM_BSWM_STARTUP = 0x02,
	FRSM_BSWM_STARTUP_ECU_PASSIVE = 0x03,
	FRSM_BSWM_WAKEUP = 0x04,
	FRSM_BSWM_WAKEUP_ECU_PASSIVE = 0x05,
	FRSM_BSWM_HALT_REQ = 0x06,
	FRSM_BSWM_HALT_REQ_ECU_PASSIVE = 0x07,
	FRSM_BSWM_KEYSLOT_ONLY = 0x08,
	FRSM_BSWM_KEYSLOT_ONLY_ECU_PASSIVE = 0x09,
	FRSM_BSWM_ONLINE = 0x0A,
	FRSM_BSWM_ONLINE_ECU_PASSIVE = 0x0B,
	FRSM_BSWM_ONLINE_PASSIVE = 0x0C,
	FRSM_BSWM_ONLINE_PASSIVE_ECU_PASSIVE = 0x0D,
	FRSM_LOW_NUMBER_OF_COLDSTARTERS = 0x0E,
	FRSM_LOW_NUMBER_OF_COLDSTARTERS_ECU_PASSIVE = 0x0F
};

//[*] Extracted 7 items.

//====================================================================================================
//[*] Processing FlexRay Tranceiver Driver (FrTrcv) - ID: 71
struct FrTrcv_ConfigType {
	implementation_specific IMPLEMENATION_SPECIFIC;
};

enum FrTrcv_TrcvModeType {
	FRTRCV_TRCVMODE_NORMAL,
	FRTRCV_TRCVMODE_STANDBY,
	FRTRCV_TRCVMODE_SLEEP,
	FRTRCV_TRCVMODE_RECEIVEONLY
};

enum FrTrcv_TrcvWUReasonType {
	FRTRCV_WU_NOT_SUPPORTED,
	FRTRCV_WU_BY_BUS,
	FRTRCV_WU_BY_PIN,
	FRTRCV_WU_INTERNALLY,
	FRTRCV_WU_RESET,
	FRTRCV_WU_POWER_ON
};

//[*] Extracted 11 items.

//====================================================================================================
//[*] Processing Function Inhibition Manager (FiM) - ID: 11
struct FiM_ConfigType {
	implementation_specific IMPLEMENATION_SPECIFIC;
};

//[*] Extracted 8 items.

//====================================================================================================
//[*] Processing GPT Driver (Gpt) - ID: 100
struct Gpt_ConfigType {
	implementation_specific IMPLEMENATION_SPECIFIC;
};

typedef uint Gpt_ChannelType;

typedef uint Gpt_ValueType;

enum Gpt_ModeType {
	GPT_MODE_NORMAL = 0x00,
	GPT_MODE_SLEEP = 0x01
};

enum Gpt_PredefTimerType {
	GPT_PREDEF_TIMER_1US_16BIT = 0x00,
	GPT_PREDEF_TIMER_1US_24BIT = 0x01,
	GPT_PREDEF_TIMER_1US_32BIT = 0x02,
	GPT_PREDEF_TIMER_100US_32BIT = 0x03
};

//[*] Extracted 14 items.

//====================================================================================================
//[*] Processing HW Test Manager on start up andshutdown (HTMSS) - ID: 17
struct HTMSS_TestCfgType {
	implementation_specific IMPLEMENATION_SPECIFIC;
};

enum HTMSS_TestStatusType {
	HTMSS_STATUS_OK,
	HTMSS_STATUS_NOK,
	HTMSS_STATUS_INVALID,
	HTMSS_STATUS_UNINIT
};

enum HTMSS_TestGroupType {
	HTMSS_STARTUP,
	HTMSS_SHUTDOWN,
	HTMSS_STARTUP_SHUTDOWN
};

struct HTMSS_TestResultType {
	uint8 TestResult;
	uint8 TestSignature;
};

//[*] Extracted 6 items.

//====================================================================================================
//[*] Processing ICU Driver (Icu) - ID: 122
enum Icu_ModeType {
	ICU_MODE_NORMAL = 0x00,
	ICU_MODE_SLEEP = 0x01
};

typedef uint Icu_ChannelType;

enum Icu_InputStateType {
	ICU_ACTIVE = 0x00,
	ICU_IDLE = 0x01
};

struct Icu_ConfigType {
	implementation_specific IMPLEMENATION_SPECIFIC;
};

enum Icu_ActivationType {
	ICU_RISING_EDGE = 0x00,
	ICU_FALLING_EDGE = 0x01,
	ICU_BOTH_EDGES = 0x02
};

typedef uint Icu_ValueType;

struct Icu_DutyCycleType {
	Icu_ValueType ActiveTime;
	Icu_ValueType PeriodTime;
};

typedef uint Icu_IndexType;

typedef uint Icu_EdgeNumberType;

enum Icu_MeasurementModeType {
	ICU_MODE_SIGNAL_EDGE_DETECT = 0x00,
	ICU_MODE_SIGNAL_MEASUREMENT = 0x01,
	ICU_MODE_TIMESTAMP = 0x02,
	ICU_MODE_EDGE_COUNTER = 0x03
};

enum Icu_SignalMeasurementPropertyType {
	ICU_LOW_TIME = 0x00,
	ICU_HIGH_TIME = 0x01,
	ICU_PERIOD_TIME = 0x02,
	ICU_DUTY_CYCLE = 0x03
};

enum Icu_TimestampBufferType {
	ICU_LINEAR_BUFFER = 0x00,
	ICU_CIRCULAR_BUFFER = 0x01
};

//[*] Extracted 26 items.

//====================================================================================================
//[*] Processing IEEE1722 Transport Layer (IEEE1722Tp) - ID: 131
struct IEEE1722Tp_ConfigType {
	implementation_specific IMPLEMENATION_SPECIFIC;
};

typedef uint16 IEEE1722Tp_StreamIndexType;

enum IEEE1722Tp_StreamStateType {
	IEEE1722TP_STREAM_ACTIVATED = 0x00,
	IEEE1722TP_STREAM_DEACTIVATED = 0x01
};

struct IEEE1722Tp_CommonStreamHeaderType {
	uint8 mr;
	uint8 tv;
	uint8 tu;
	uint64 mac_address;
	uint32 unique_id;
	uint64 avtp_timestamp;
	uint8 avtp_timestamp_provided;
};

struct IEEE1722Tp_TxIec68133IidcType {
	uint8 sy;
};

struct IEEE1722Tp_RxIec68133IidcType {
	uint8 tag;
	uint8 channel;
	uint8 tcode;
	uint8 sy;
};

struct IEEE1722Tp_TxIec68133Type {
	uint16 dbc;
	uint8 qpc;
	uint8 sy;
};

struct IEEE1722Tp_RxIec68133Type {
	uint8 tag;
	uint8 channel;
	uint8 tcode;
	uint8 sy;
	uint8 qi_1;
	uint8 sid;
	uint16 dbs;
	uint8 fn;
	uint8 qpc;
	uint8 sph;
	uint16 dpc;
	uint8 qi_2;
	uint8 fmt;
};

struct IEEE1722Tp_TxIec68133CipNoSphType {
	uint16 dbc;
	uint8 qpc;
	uint8 sy;
	uint16 fdf;
};

struct IEEE1722Tp_RxIec68133CipNoSphType {
	uint8 tag;
	uint8 channel;
	uint8 tcode;
	uint8 sy;
	uint8 qi_1;
	uint8 sid;
	uint8 dbs;
	uint8 fn;
	uint8 qpc;
	uint8 sph;
	uint16 dbc;
	uint8 qi_2;
	uint8 fmt;
	uint16 fdf;
	uint32 syt;
};

struct IEEE1722Tp_TxIec68133CipWithSphType {
	uint16 dbc;
	uint8 qpc;
	uint8 sy;
	uint32 fdf;
};

struct IEEE1722Tp_RxIec68133CipWithSphType {
	uint8 tag;
	uint8 channel;
	uint8 tcode;
	uint8 sy;
	uint8 qi_1;
	uint8 sid;
	uint16 dbs;
	uint8 fn;
	uint8 qpc;
	uint8 sph;
	uint16 dbc;
	uint8 qi_2;
	uint8 fmt;
	uint32 fdf;
};

struct IEEE1722Tp_TxAafPcmType {
	uint8 evt;
};

struct IEEE1722Tp_RxAafPcmType {
	uint16 format;
	uint8 sp;
	uint8 evt;
	uint8 nsr;
	uint16 channels_per_frame;
	uint16 bit_depth;
};

struct IEEE1722Tp_TxAafAes3Type {
	uint8 evt;
};

struct IEEE1722Tp_RxAafAes3Type {
	uint16 format;
	uint8 sp;
	uint8 evt;
	uint8 nfr;
	uint16 streams_per_frame;
	uint16 aes3_data_type_h;
	uint8 aes3_dt_ref;
	uint16 aes3_data_type_l;
};

struct IEEE1722Tp_TxRvfType {
	uint8 ap;
	uint8 f;
	uint8 ef;
	uint8 evt;
	uint8 pd;
	uint8 num_lines;
	uint16 i_seq_num;
	uint32 line_number;
};

struct IEEE1722Tp_RxRvfType {
	uint32 active_pixels;
	uint32 total_lines;
	uint8 ap;
	uint8 f;
	uint8 ef;
	uint8 evt;
	uint8 pd;
	uint8 i;
	uint8 pixel_depth;
	uint8 pixel_format;
	uint16 frame_rate;
	uint8 colorspace;
	uint8 num_lines;
	uint16 i_seq_num;
	uint32 line_number;
};

struct IEEE1722Tp_TxCrfType {
	uint8 mr;
	uint8 tu;
	uint64 mac_address;
	uint32 unique_id;
	uint8 fs;
};

struct IEEE1722Tp_RxCrfType {
	uint8 mr;
	uint8 tu;
	uint64 mac_address;
	uint32 unique_id;
	uint8 fs;
	uint16 type;
	uint8 pull;
	uint32 base_frequency;
	uint32 timestamp_interval;
};

//[*] Extracted 11 items.

//====================================================================================================
//[*] Processing Intrusion Detection SystemManager (IdsM) - ID: 108
struct IdsM_ConfigType {
	implementation_specific IMPLEMENATION_SPECIFIC;
};

typedef uint16 IdsM_Filters_BlockStateType;

typedef uint8 IdsM_Filters_ReportingModeType;

typedef uint64 IdsM_TimestampType;

typedef uint16 IdsM_ExternalSecurityEventIdType;

//[*] Extracted 16 items.

//====================================================================================================
//[*] Processing IO HW Abstraction (no prefix
struct IoHwAb_Init_Id_ConfigType {
	implementation_specific IMPLEMENATION_SPECIFIC;
};

//[*] Extracted 13 items.

//====================================================================================================
//[*] Processing IPDU Multiplexer (IpduM) - ID: 52
struct IpduM_ConfigType {
	implementation_specific IMPLEMENATION_SPECIFIC;
};

//[*] Extracted 8 items.

//====================================================================================================
//[*] Processing Key Manager (KeyM) - ID: 109
struct KeyM_ConfigType {
	implementation_specific IMPLEMENATION_SPECIFIC;
};

enum KeyM_KH_UpdateOperationType {
	KEYM_KH_UPDATE_KEY_UPDATE_REPEAT = 0x01,
	KEYM_KH_UPDATE_FINISH = 0x02
};

struct KeyM_CertElementIteratorType {
	implementation_specific IMPLEMENATION_SPECIFIC;
};

typedef uint16 KeyM_CryptoKeyIdType;

//[*] Extracted 23 items.

//====================================================================================================
//[*] Processing Large Data COM (LdCom) - ID: 49
struct LdCom_ConfigType {
	implementation_specific IMPLEMENATION_SPECIFIC;
};

//[*] Extracted 12 items.

//====================================================================================================
//[*] Processing LIN Driver (Lin) - ID: 82
struct Lin_ConfigType {
	implementation_specific IMPLEMENATION_SPECIFIC;
};

typedef uint8 Lin_FramePidType;

enum Lin_FrameCsModelType {
	LIN_ENHANCED_CS,
	LIN_CLASSIC_CS
};

enum Lin_FrameResponseType {
	LIN_FRAMERESPONSE_TX,
	LIN_FRAMERESPONSE_RX,
	LIN_FRAMERESPONSE_IGNORE
};

typedef uint8 Lin_FrameDlType;

struct Lin_PduType {
	Lin_FramePidType Pid;
	Lin_FrameCsModelType Cs;
	Lin_FrameResponseType Drc;
	Lin_FrameDlType Dl;
	uint8* SduPtr;
};

enum Lin_StatusType {
	LIN_NOT_OK,
	LIN_TX_OK,
	LIN_TX_BUSY,
	LIN_TX_HEADER_ERROR,
	LIN_TX_ERROR,
	LIN_RX_OK,
	LIN_RX_BUSY,
	LIN_RX_ERROR,
	LIN_RX_NO_RESPONSE,
	LIN_OPERATIONAL,
	LIN_CH_SLEEP
};

enum Lin_SlaveErrorType {
	LIN_ERR_HEADER,
	LIN_ERR_RESP_STOPBIT,
	LIN_ERR_RESP_CHKSUM,
	LIN_ERR_RESP_DATABIT,
	LIN_ERR_NO_RESP,
	LIN_ERR_INC_RESP
};

//[*] Extracted 9 items.

//====================================================================================================
//[*] Processing LIN Interface (LinIf) - ID: 62
typedef uint8 LinIf_SchHandleType;

struct LinIf_ConfigType {
	implementation_specific IMPLEMENATION_SPECIFIC;
};

struct LinTp_ConfigType {
	implementation_specific IMPLEMENATION_SPECIFIC;
};

enum LinTp_Mode {
	LINTP_APPLICATIVE_SCHEDULE,
	LINTP_DIAG_REQUEST,
	LINTP_DIAG_RESPONSE
};

//[*] Extracted 29 items.

//====================================================================================================
//[*] Processing LIN State Manager (LinSM) - ID: 141
typedef uint8 LinSM_ModeType;

struct LinSM_ConfigType {
	implementation_specific IMPLEMENATION_SPECIFIC;
};

//[*] Extracted 10 items.

//====================================================================================================
//[*] Processing LIN Transceiver Driver (LinTrcv) - ID: 64
struct LinTrcv_ConfigType {
	implementation_specific IMPLEMENATION_SPECIFIC;
};

enum LinTrcv_TrcvModeType {
	LINTRCV_TRCV_MODE_NORMAL,
	LINTRCV_TRCV_MODE_STANDBY,
	LINTRCV_TRCV_MODE_SLEEP
};

enum LinTrcv_TrcvWakeupModeType {
	LINTRCV_WUMODE_ENABLE,
	LINTRCV_WUMODE_DISABLE,
	LINTRCV_WUMODE_CLEAR
};

enum LinTrcv_TrcvWakeupReasonType {
	LINTRCV_WU_ERROR,
	LINTRCV_WU_NOT_SUPPORTED,
	LINTRCV_WU_BY_BUS,
	LINTRCV_WU_BY_PIN,
	LINTRCV_WU_INTERNALLY,
	LINTRCV_WU_RESET,
	LINTRCV_WU_POWER_ON
};

//[*] Extracted 7 items.

//====================================================================================================
//[*] Processing LSDU Router (LSduR) - ID: 132
struct LSduR_PBConfigType {
	implementation_specific IMPLEMENATION_SPECIFIC;
};

typedef uint16 LSduR_PBConfigIdType;

enum LSduR_StateType {
	LSDUR_UNINIT,
	LSDUR_ONLINE
};

//[*] Extracted 9 items.

//====================================================================================================
//[*] Processing MACsec Key Agreement (Mka) - ID: 151
enum Mka_ValidateFramesType {
	MKA_VALIDATE_DISABLED = 0,
	MKA_VALIDATE_CHECKED = 1,
	MKA_VALIDATE_STRICT = 2
};

enum Mka_ConfidentialityOffsetType {
	MKA_CONFIDENTIALITY_NONE = 0,
	MKA_CONFIDENTIALITY_OFFSET_0 = 1,
	MKA_CONFIDENTIALITY_OFFSET_30 = 2,
	MKA_CONFIDENTIALITY_OFFSET_50 = 3
};

enum Mka_PermisiveModeType {
	NEVER_Mka = 0,
	TIMEOUT_Mka = 1
};

enum Mka_MkaStatus {
	MKA_STATUS_MACSEC_RUNNING = 0,
	MKA_STATUS_WAITING_PEER_LINK = 1,
	MKA_STATUS_WAITING_PEER = 2,
	MKA_STATUS_IN_PROGRESS = 3,
	MKA_STATUS_AUTH_FAIL_UNKNOWN_PEER = 4,
	MKA_STATUS_UNDEFINED = 0xFF
};

struct Mka_MacSecConfigType {
	boolean ProtectFrames;
	boolean ReplayProtect;
	uint32 ReplayWindow;
	Mka_ValidateFramesType ValidateFrames;
	uint64 CurrentCipherSuite;
	Mka_ConfidentialityOffsetType ConfidentialityOffset;
	boolean ControlledPortEnabled;
	const uint16* BypassedVlanPtrs;
	uint8 BypassedVlansLength;
	const uint16* BypassedEtherTypesPtr;
	uint8 BypassedEtherTypesLength;
};



struct Mka_Stats_Tx_SecYType {
	uint64 OutPkts_Untagged;
	uint64 OutPkts_TooLong;
	uint64 OutOctets_Protected;
	uint64 OutOctets_Encrypted;
};

struct Mka_Stats_Rx_SecYType {
	uint64 InPkts_Untagged;
	uint64 InPkts_NoTag;
	uint64 InPkts_BadTag;
	uint64 InPkts_NoSa;
	uint64 InPkts_NoSaError;
	uint64 InPkts_Overrun;
	uint64 InOctets_Validated;
	uint64 InOctets_Decrypted;
};

struct Mka_Stats_Tx_ScType {
	uint64 OutPkts_Protected;
	uint64 OutPkts_Encrypted;
};

struct Mka_Stats_Rx_ScType {
	uint64 InPkts_Ok;
	uint64 InPkts_Unchecked;
	uint64 InPkts_Delayed;
	uint64 InPkts_Late;
	uint64 InPkts_Invalid;
	uint64 InPkts_NotValid;
};

struct Mka_SakKeyPtrType {
	const uint8* HashKeyPtr;
	const uint8* SakKeyPtr;
	const uint8* SaltKeyPtr;
};



struct Mka_Stats_SecYType {
	Mka_Stats_Tx_SecYType StatsTxPhy;
	Mka_Stats_Rx_SecYType StatsRxPhy;
	Mka_Stats_Tx_ScType StatsTxSc;
	Mka_Stats_Rx_ScType StatsRxSc;
};

struct Mka_PaeStatusType {
	Mka_MkaStatus ConnectionStatus;
	uint64 PeerSci;
	unsigned char CknInUse[32];
};



struct Mka_ConfigType {
	implementation_specific IMPLEMENATION_SPECIFIC;
};

//[*] Extracted 18 items.

//====================================================================================================
//[*] Processing MCU Driver (Mcu) - ID: 101
struct Mcu_ConfigType {
	implementation_specific IMPLEMENATION_SPECIFIC;
};

enum Mcu_PllStatusType {
	MCU_PLL_LOCKED = 0x00,
	MCU_PLL_UNLOCKED = 0x01,
	MCU_PLL_STATUS_UNDEFINED = 0x02
};

typedef uint Mcu_ClockType;

enum Mcu_ResetType {
	MCU_POWER_ON_RESET = 0x00,
	MCU_WATCHDOG_RESET = 0x01,
	MCU_SW_RESET = 0x02,
	MCU_RESET_UNDEFINED = 0x03
};

typedef uint Mcu_RawResetType;

typedef uint Mcu_ModeType;

typedef uint Mcu_RamSectionType;

enum Mcu_RamStateType {
	MCU_RAMSTATE_INVALID = 0x00,
	MCU_RAMSTATE_VALID = 0x01
};

//[*] Extracted 11 items.

//====================================================================================================
//[*] Processing Memory Abstraction Interface (MemIf) - ID: 22
enum MemIf_StatusType {
	MEMIF_UNINIT,
	MEMIF_IDLE,
	MEMIF_BUSY,
	MEMIF_BUSY_INTERNAL
};

enum MemIf_JobResultType {
	MEMIF_JOB_OK,
	MEMIF_JOB_FAILED,
	MEMIF_JOB_PENDING,
	MEMIF_JOB_CANCELED,
	MEMIF_BLOCK_INCONSISTENT,
	MEMIF_BLOCK_INVALID
};

//[*] Extracted 8 items.

//====================================================================================================
//[*] Processing Memory Access (MemAcc) - ID: 41

typedef uint8 MemAcc_DataType;

enum MemAcc_JobResultType {
	MEMACC_OK = 0x00,
	MEMACC_FAILED = 0x01,
	MEMACC_INCONSISTENT = 0x02,
	MEMACC_CANCELED = 0x03,
	MEMACC_ECC_UNCORRECTED = 0x04,
	MEMACC_ECC_CORRECTED = 0x05
};

enum MemAcc_JobStatusType {
	MEMACC_JOB_IDLE = 0x00,
	MEMACC_JOB_PENDING = 0x01
};

enum MemAcc_JobType {
	MEMACC_NO_JOB = 0x00,
	MEMACC_WRITE_JOB = 0x01,
	MEMACC_READ_JOB = 0x02,
	MEMACC_COMPARE_JOB = 0x03,
	MEMACC_ERASE_JOB = 0x04,
	MEMACC_MEMHWSPECIFIC_JOB = 0x05,
	MEMACC_BLANKCHECK_JOB = 0x06,
	MEMACC_REQUESTLOCK_JOB = 0x07
};

enum MemAcc_MemJobResultType {
	MEM_JOB_OK = 0x00,
	MEM_JOB_PENDING = 0x01,
	MEM_JOB_FAILED = 0x02,
	MEM_INCONSISTENT = 0x03,
	MEM_ECC_UNCORRECTED = 0x04,
	MEM_ECC_CORRECTED = 0x05
};

enum MemAcc_HwIdType {
};



struct MemAcc_MemConfigType {
	implementation_specific IMPLEMENATION_SPECIFIC;
};

typedef uint16 MemAcc_AddressAreaIdType;

typedef uint32 MemAcc_AddressType;

typedef uint8 MemAcc_MemDataType;

typedef uint32 MemAcc_MemInstanceIdType;

typedef uint32 MemAcc_MemLengthType;

typedef uint32 MemAcc_MemHwServiceIdType;

typedef MemAcc_AddressType MemAcc_MemAddressType;

typedef void (*MemAcc_MemInitFuncType) (MemAcc_MemConfigType* configPtr);

typedef void (*MemAcc_MemDeInitFuncType) (void);

typedef MemAcc_MemJobResultType (*MemAcc_MemGetJobResultFuncType) (MemAcc_MemInstanceIdType instanceId);

typedef void (*MemAcc_MemSuspendFuncType) (MemAcc_MemInstanceIdType instanceId);

typedef void (*MemAcc_MemResumeFuncType) (MemAcc_MemInstanceIdType instanceId);

typedef void (*MemAcc_MemPropagateErrorFuncType) (MemAcc_MemInstanceIdType instanceId);

typedef Std_ReturnType (*MemAcc_MemReadFuncType) (MemAcc_MemInstanceIdType instanceId,MemAcc_MemAddressType sourceAddress,MemAcc_MemLengthType length,MemAcc_MemDataType* destinationDataPtr);

typedef void (*MemAcc_MemWriteFuncType) (Std_ReturnType ret,MemAcc_MemInstanceIdType instanceId,MemAcc_MemAddressType targetAddress,const MemAcc_MemDataType* sourceDataPtr,MemAcc_MemLengthType length);

typedef void (*MemAcc_MemEraseFuncType) (Std_ReturnType ret,MemAcc_MemInstanceIdType instanceId,MemAcc_MemAddressType targetAddress,MemAcc_MemLengthType length);

typedef void (*MemAcc_MemBlankCheckFuncType) (Std_ReturnType ret,MemAcc_MemInstanceIdType instanceId,MemAcc_MemAddressType targetAddress,MemAcc_MemLengthType length);

typedef void (*MemAcc_MemHwSpecificServiceFuncType) (Std_ReturnType ret,MemAcc_MemInstanceIdType instanceId,MemAcc_MemHwServiceIdType hwServiceId,MemAcc_MemDataType* dataPtr,MemAcc_MemLengthType* lengthPtr);

typedef void (*MemAcc_MemMainFuncType) (void);

struct MemAcc_ConfigType {
	implementation_specific IMPLEMENATION_SPECIFIC;
};



typedef uint32 MemAcc_LengthType;

struct MemAcc_MemoryInfoType {
	MemAcc_AddressType LogicalStartAddress;
	MemAcc_AddressType PhysicalStartAddress;
	MemAcc_LengthType MaxOffset;
	uint32 EraseSectorSize;
	uint32 EraseSectorBurstSize;
	uint32 MinReadSize;
	uint32 WritePageSize;
	uint32 MaxReadSize;
	uint32 WritePageBurstSize;
	uint32 HwId;
};

struct MemAcc_JobInfoType {
	MemAcc_AddressType LogicalAddress;
	MemAcc_LengthType Length;
	MemAcc_HwIdType HwId;
	uint32 MemInstanceId;
	uint32 MemAddress;
	uint32 MemLength;
	MemAcc_JobType CurrentJob;
	MemAcc_MemJobResultType MemResult;
};



struct MemAcc_MemBinaryHeaderType {
	uint64 UniqueId;
	uint64 Flags;
	uint64 Header;
	uint64 Delimiter;
	MemAcc_MemInitFuncType* InitFunc;
	MemAcc_MemMainFuncType* MainFunc;
	MemAcc_MemGetJobResultFuncType* GetJobResultFunc;
	MemAcc_MemReadFuncType* ReadFunc;
	MemAcc_MemWriteFuncType* WriteFunc;
	MemAcc_MemEraseFuncType* EraseFunc;
	MemAcc_MemPropagateErrorFuncType* PropagateErrorFunc;
	MemAcc_MemBlankCheckFuncType* BlankCheckFunc;
	MemAcc_MemSuspendFuncType* SuspendFunc;
	MemAcc_MemResumeFuncType* ResumeFunc;
	MemAcc_MemHwSpecificServiceFuncType* HwSpecificServiceFunc;
};





//[*] Extracted 20 items.

//====================================================================================================
//[*] Processing Memory Driver (Mem) - ID: 91
typedef MemAcc_AddressType Mem_AddressType;

struct Mem_ConfigType {
	implementation_specific IMPLEMENATION_SPECIFIC;
};

typedef uint8 Mem_DataType;

typedef uint32 Mem_InstanceIdType;

typedef uint32 Mem_LengthType;

typedef uint32 Mem_HwServiceIdType;

//[*] Extracted 13 items.

//====================================================================================================
//[*] Processing Network Management Interface (Nm) - ID: 29
enum Nm_ModeType {
	NM_MODE_BUS_SLEEP,
	NM_MODE_PREPARE_BUS_SLEEP,
	NM_MODE_SYNCHRONIZE,
	NM_MODE_NETWORK
};

enum Nm_StateType {
	NM_STATE_UNINIT = 0x00,
	NM_STATE_BUS_SLEEP = 0x01,
	NM_STATE_PREPARE_BUS_SLEEP = 0x02,
	NM_STATE_READY_SLEEP = 0x03,
	NM_STATE_NORMAL_OPERATION = 0x04,
	NM_STATE_REPEAT_MESSAGE = 0x05,
	NM_STATE_SYNCHRONIZE = 0x06,
	NM_STATE_OFFLINE = 0x07
};

enum Nm_BusNmType {
	NM_BUSNM_CANNM,
	NM_BUSNM_FRNM,
	NM_BUSNM_UDPNM,
	NM_BUSNM_GENERICNM,
	NM_BUSNM_UNDEF,
	NM_BUSNM_J1939NM,
	NM_BUSNM_LOCALNM
};

struct Nm_ConfigType {
	implementation_specific IMPLEMENATION_SPECIFIC;
};

//[*] Extracted 39 items.

//====================================================================================================
//[*] Processing NVRAM Manager (NvM) - ID: 20
struct NvM_ConfigType {
	implementation_specific IMPLEMENATION_SPECIFIC;
};

enum NvM_RequestResultType {
	NVM_REQ_OK = 0x00,
	NVM_REQ_NOT_OK = 0x01,
	NVM_REQ_PENDING = 0x02,
	NVM_REQ_INTEGRITY_FAILED = 0x03,
	NVM_REQ_BLOCK_SKIPPED = 0x04,
	NVM_REQ_NV_INVALIDATED = 0x05,
	NVM_REQ_CANCELED = 0x06,
	NVM_REQ_RESTORED_DEFAULTS = 0x08
};

enum NvM_MultiBlockRequestType {
	NVM_READ_ALL = 0x00,
	NVM_WRITE_ALL = 0x01,
	NVM_VALIDATE_ALL = 0x02,
	NVM_FIRST_INIT_ALL = 0x03,
	NVM_CANCEL_WRITE_ALL = 0x04
};

enum NvM_BlockRequestType {
	NVM_READ_BLOCK = 0x00,
	NVM_WRITE_BLOCK = 0x01,
	NVM_RESTORE_BLOCK_DEFAULTS = 0x02,
	NVM_ERASE_NV_BLOCK = 0x03,
	NVM_INVALIDATE_NV_BLOCK = 0x04,
	NVM_READ_ALL_BLOCK = 0x05
};

typedef uint16 NvM_BlockIdType;

//[*] Extracted 24 items.

//====================================================================================================
//[*] Processing OCU Driver (Ocu) - ID: 125
typedef uint Ocu_ChannelType;

typedef uint Ocu_ValueType;

enum Ocu_PinStateType {
	OCU_HIGH = 0x00,
	OCU_LOW = 0x01
};

enum Ocu_PinActionType {
	OCU_SET_HIGH = 0x00,
	OCU_SET_LOW = 0x01,
	OCU_TOGGLE = 0x02,
	OCU_DISABLE = 0x03
};

struct Ocu_ConfigType {
	implementation_specific IMPLEMENATION_SPECIFIC;
};

enum Ocu_ReturnType {
	OCU_CM_IN_REF_INTERVAL = 0x00,
	OCU_CM_OUT_REF_INTERVAL = 0x01
};

//[*] Extracted 12 items.

//====================================================================================================
//[*] Processing OS (Os)
typedef uint32 ApplicationType;

enum ApplicationStateType {
    APPLICATION_ACCESSIBLE,
    APPLICATION_RESTARTING,
    APPLICATION_TERMINATED
};

typedef ApplicationStateType* ApplicationStateRefType;

typedef uint32 TrustedFunctionIndexType;

typedef void* TrustedFunctionParameterRefType;

typedef uint32 AccessType;

typedef implementation_specific ObjectAccessType;
typedef implementation_specific ObjectTypeType;
typedef implementation_specific MemorySizeType;
typedef implementation_specific ISRType;
typedef implementation_specific ScheduleTableType;
typedef implementation_specific ScheduleTableStatusType;
typedef ScheduleTableStatusType* ScheduleTableStatusRefType;

typedef implementation_specific ProtectionReturnType;
typedef implementation_specific RestartType;
typedef implementation_specific PhysicalTimeType;
enum CoreIdType {
    OS_CORE_ID_MASTER,
    OS_CORE_ID_0,
    OS_CORE_ID_1,
    OS_CORE_ID_2,
    OS_CORE_ID_3,
    OS_CORE_ID_4,
    OS_CORE_ID_5,
    OS_CORE_ID_6,
    OS_CORE_ID_7,
    OS_CORE_ID_8,
    OS_CORE_ID_9

};

enum SpinlockIdType {
    INVALID_SPINLOCK
};

enum TryToGetSpinlockType {
	TRYTOGETSPINLOCK_SUCCESS,
	TRYTOGETSPINLOCK_NOSUCCESS
};

enum IdleModeType {
    IDLE_NO_HALT
};

typedef uint16 AreaIdType;

//[*] Extracted 54 items.

//====================================================================================================
//[*] Processing PDU Router (PduR) - ID: 51
struct PduR_PBConfigType {
	implementation_specific IMPLEMENATION_SPECIFIC;
};

typedef uint16 PduR_PBConfigIdType;

typedef uint16 PduR_RoutingPathGroupIdType;

enum PduR_StateType {
	PDUR_UNINIT,
	PDUR_ONLINE
};

//[*] Extracted 16 items.

//====================================================================================================
//[*] Processing Port Driver (Port) - ID: 124
struct Port_ConfigType {
	implementation_specific IMPLEMENATION_SPECIFIC;
};

typedef uint Port_PinType;

enum Port_PinDirectionType {
	PORT_PIN_IN = 0x00,
	PORT_PIN_OUT = 0x01
};

typedef uint Port_PinModeType;

//[*] Extracted 5 items.

//====================================================================================================
//[*] Processing PWM Driver (Pwm) - ID: 121
typedef uint Pwm_ChannelType;

typedef uint Pwm_PeriodType;

enum Pwm_OutputStateType {
	PWM_HIGH = 0x00,
	PWM_LOW = 0x01
};

enum Pwm_EdgeNotificationType {
	PWM_RISING_EDGE = 0x00,
	PWM_FALLING_EDGE = 0x01,
	PWM_BOTH_EDGES = 0x02
};

enum Pwm_ChannelClassType {
	PWM_VARIABLE_PERIOD = 0x00,
	PWM_FIXED_PERIOD = 0x01,
	PWM_FIXED_PERIOD_SHIFTED = 0x02
};

struct Pwm_ConfigType {
	implementation_specific IMPLEMENATION_SPECIFIC;
};

enum Pwm_PowerStateRequestResultType {
	PWM_SERVICE_ACCEPTED = 0x00,
	PWM_NOT_INIT = 0x01,
	PWM_SEQUENCE_ERROR = 0x02,
	PWM_HW_FAILURE = 0x03,
	PWM_POWER_STATE_NOT_SUPP = 0x04,
	PWM_TRANS_NOT_POSSIBLE = 0x05
};

enum Pwm_PowerStateType {
	PWM_FULL_POWER = 0x00
};

//[*] Extracted 14 items.

//====================================================================================================
//[*] Processing RAM Test (RamTst) - ID: 93
struct RamTst_ConfigType {
	implementation_specific IMPLEMENATION_SPECIFIC;
};

enum RamTst_ExecutionStatusType {
	RAMTST_EXECUTION_UNINIT = 0x00,
	RAMTST_EXECUTION_STOPPED = 0x01,
	RAMTST_EXECUTION_RUNNING = 0x02,
	RAMTST_EXECUTION_SUSPENDED = 0x03
};

enum RamTst_TestResultType {
	RAMTST_RESULT_NOT_TESTED = 0x00,
	RAMTST_RESULT_OK = 0x01,
	RAMTST_RESULT_NOT_OK = 0x02,
	RAMTST_RESULT_UNDEFINED = 0x03
};

typedef uint8 RamTst_AlgParamsIdType;

enum RamTst_AlgorithmType {
	RAMTST_ALGORITHM_UNDEFINED = 0x00,
	RAMTST_CHECKERBOARD_TEST = 0x01,
	RAMTST_MARCH_TEST = 0x02,
	RAMTST_WALK_PATH_TEST = 0x03,
	RAMTST_GALPAT_TEST = 0x04,
	RAMTST_TRANSP_GALPAT_TEST = 0x05,
	RAMTST_ABRAHAM_TEST = 0x06
};

typedef uint32 RamTst_NumberOfTestedCellsType;

typedef uint16 RamTst_NumberOfBlocksType;

//[*] Extracted 18 items.

//====================================================================================================
//[*] Processing RTE (Rte) - ID: 2
//====================================================================================================
//[*] Processing SAE J1939 DiagnosticCommunication Manager (J1939Dcm) - ID: 58
struct J1939Dcm_ConfigType {
	implementation_specific IMPLEMENATION_SPECIFIC;
};

enum J1939Dcm_StateType {
	J1939DCM_STATE_ONLINE = 0x00,
	J1939DCM_STATE_OFFLINE = 0x01
};

//[*] Extracted 15 items.

//====================================================================================================
//[*] Processing SAE J1939 Network Management (J1939Nm) - ID: 34
struct J1939Nm_ConfigType {
	implementation_specific IMPLEMENATION_SPECIFIC;
};

//[*] Extracted 13 items.

//====================================================================================================
//[*] Processing SAE J1939 Request Manager (J1939Rm) - ID: 59
struct J1939Rm_ConfigType {
	implementation_specific IMPLEMENATION_SPECIFIC;
};

enum J1939Rm_StateType {
	J1939RM_STATE_OFFLINE = 0x00,
	J1939RM_STATE_ONLINE = 0x01
};

//[*] Extracted 14 items.

//====================================================================================================
//[*] Processing SAE J1939 Transport Layer (J1939Tp) - ID: 37
struct J1939Tp_ConfigType {
	implementation_specific IMPLEMENATION_SPECIFIC;
};

//[*] Extracted 10 items.

//====================================================================================================
//[*] Processing Secure Onboard Communication (SecOC) - ID: 150
struct SecOC_ConfigType {
	implementation_specific IMPLEMENATION_SPECIFIC;
};

enum SecOC_StateType {
	SECOC_UNINIT,
	SECOC_INIT
};

//[*] Extracted 24 items.

//====================================================================================================
//[*] Processing Service Discovery (Sd) - ID: 171
struct Sd_ConfigType {
	implementation_specific IMPLEMENATION_SPECIFIC;
};

enum Sd_ServerServiceSetStateType {
	SD_SERVER_SERVICE_DOWN = 0x00,
	SD_SERVER_SERVICE_AVAILABLE = 0x01
};

enum Sd_ClientServiceSetStateType {
	SD_CLIENT_SERVICE_RELEASED = 0x00,
	SD_CLIENT_SERVICE_REQUESTED = 0x01
};

enum Sd_ConsumedEventGroupSetStateType {
	SD_CONSUMED_EVENTGROUP_RELEASED = 0x00,
	SD_CONSUMED_EVENTGROUP_REQUESTED = 0x01
};

enum Sd_ClientServiceCurrentStateType {
	SD_CLIENT_SERVICE_DOWN = 0x00,
	SD_CLIENT_SERVICE_AVAILABLE = 0x01
};

enum Sd_ConsumedEventGroupCurrentStateType {
	SD_CONSUMED_EVENTGROUP_DOWN = 0x00,
	SD_CONSUMED_EVENTGROUP_AVAILABLE = 0x01
};

enum Sd_EventHandlerCurrentStateType {
	SD_EVENT_HANDLER_RELEASED = 0x00,
	SD_EVENT_HANDLER_REQUESTED = 0x01
};

typedef uint16 Sd_ServiceGroupIdType;

enum Sd_AclUpdateType {
	SD_ACL_ADD_PROVIDER = 0x00,
	SD_ACL_ADD_CONSUMER = 0x01,
	SD_ACL_REMOVE_PROVIDER = 0x02,
	SD_ACL_REMOVE_CONSUMER = 0x03
};

//[*] Extracted 14 items.

//====================================================================================================
//[*] Processing Socket Adaptor (SoAd) - ID: 56
typedef uint16 SoAd_SoConIdType;

enum SoAd_SoConModeType {
	SOAD_SOCON_ONLINE,
	SOAD_SOCON_RECONNECT,
	SOAD_SOCON_OFFLINE
};

typedef uint16 SoAd_RoutingGroupIdType;

struct SoAd_ConfigType {
	implementation_specific IMPLEMENATION_SPECIFIC;
};

typedef uint8 SoAd_MeasurementIdxType;

//[*] Extracted 37 items.

//====================================================================================================
//[*] Processing Software Cluster Connection (SwCluC) - ID: 16
typedef uint8 SwCluC_BManif_SwClusterIdType;

typedef uint8 SwCluC_BManif_MachineIdType;

typedef uint16 SwCluC_BManif_ConCtrlType;

enum SwCluC_BManif_ResourcePropertiesType {
	SWCLUC_BMANIF_PROVIDED_RESOURCE = 0x80,
	SWCLUC_BMANIF_MANDATORY_RESOURCE = 0x40
};

typedef uint8 SwCluC_BManif_ResourceTypeIdType;

typedef uint32 SwCluC_BManif_GlobalResourceIdType;

typedef uint32 SwCluC_BManif_ResourceGuardValueType;

typedef uint16 SwCluC_BManif_TableIndexType;

typedef uint8 SwCluC_BManif_HandleIndexType;

typedef int (*SwCluC_BManif_VoidFncPtrType) (void);

union SwCluC_BManif_HandleType {
	void* dptr;
	uint32 val;
	SwCluC_BManif_VoidFncPtrType fptr;
};

struct SwCluC_BManif_HeaderType {
	uint64 Preamble;
	uint8 ManifestMajorVersion;
	uint8 ManifestMinorVersion;
	SwCluC_BManif_SwClusterIdType SwClusterId;
	SwCluC_BManif_MachineIdType MachineId;
	uint8 SwClusterType;
	uint8 Reserved1;
	uint8 Reserved2;
	uint8 Reserved3;
	SwCluC_BManif_ConCtrlType ConnectorControlFlags;
	uint16 NoOfInterfaceDescriptors;
	uint16 NoOfOfferedInterfaceHandles;
	uint16 NoOfSubscribedInterfaceHandles;
	const uint32* ImmutableTablesChecksumPtr;
	const uint32* SubscribedInterfaceValidityMarkerPtr;
	const SwCluC_BManif_ResourcePropertiesType* ResourcePropertiesDescriptorColumnPtr;
	const SwCluC_BManif_ResourceTypeIdType* ResourceTypeDescriptorColumnPtr;
	const SwCluC_BManif_GlobalResourceIdType* GlobalResourceIdDescriptorColumnPtr;
	const SwCluC_BManif_ResourceGuardValueType* ResourceGuardValueDescriptorColumnPtr;
	const SwCluC_BManif_TableIndexType* OfferedInterfaceIndexDescriptorColumnPtr;
	const SwCluC_BManif_HandleIndexType* OfferedInterfaceNoOfHandlesDescriptorColumnPtr;
	const SwCluC_BManif_TableIndexType* SubscribedInterfaceIndexDescriptorColumnPtr;
	const SwCluC_BManif_HandleIndexType* SubscribedInterfaceNoOfHandlesDescriptorColumnPtr;
	const SwCluC_BManif_HandleIndexType* SubscribedInterfaceNoOfHandleSetsDescriptorColumnPtr;
	const SwCluC_BManif_HandleType* OfferedInterfaceHandleColumnPtr;
	const SwCluC_BManif_HandleType* SubscribedInterfaceDefaultHandleColumnPtr;
	const SwCluC_BManif_HandleType* SubscribedInterfaceHandleColumnPtr;
	const SwCluC_BManif_SwClusterIdType* SubscribedInterfaceConnectedSwClusterIdColumnPtr;
};

//[*] Extracted 102 items.

//====================================================================================================
//[*] Processing SOME/IP Transformer (SomeIpXf) - ID: 174
struct SomeIpXf_ConfigType {
	implementation_specific IMPLEMENATION_SPECIFIC;
};

//[*] Extracted 6 items.

//====================================================================================================
//[*] Processing SOME/IP Transport Protocol (SomeIpTp) - ID: 177
struct SomeIpTp_ConfigType {
	implementation_specific IMPLEMENATION_SPECIFIC;
};

//[*] Extracted 8 items.

//====================================================================================================
//[*] Processing SPI Handler Driver (Spi) - ID: 83
struct Spi_ConfigType {
	implementation_specific IMPLEMENATION_SPECIFIC;
};

enum Spi_StatusType {
	SPI_UNINIT = 0x00,
	SPI_IDLE = 0x01,
	SPI_BUSY = 0x02
};

enum Spi_JobResultType {
	SPI_JOB_OK = 0x00,
	SPI_JOB_PENDING = 0x01,
	SPI_JOB_FAILED = 0x02,
	SPI_JOB_QUEUED = 0x03
};

enum Spi_SeqResultType {
	SPI_SEQ_OK = 0x00,
	SPI_SEQ_PENDING = 0x01,
	SPI_SEQ_FAILED = 0x02,
	SPI_SEQ_CANCELED = 0x03
};

typedef uint8 Spi_DataBufferType;

typedef uint16 Spi_NumberOfDataType;

typedef uint8 Spi_ChannelType;

typedef uint16 Spi_JobType;

typedef uint8 Spi_SequenceType;

typedef uint8 Spi_HWUnitType;

enum Spi_AsyncModeType {
	SPI_POLLING_MODE = 0x00,
	SPI_INTERRUPT_MODE = 0x01
};

//[*] Extracted 15 items.

//====================================================================================================
//[*] Processing Synchronized Time-Base Manager (StbM) - ID: 160
enum Std_ReturnType_StbM {
	E_OK_StbM = 0x00,
	E_NOT_OK_StbM = 0x01
};

struct StbM_ConfigType {
	implementation_specific IMPLEMENATION_SPECIFIC;
};

struct StbM_MeasurementType {
	uint32 pathDelay;
	Eth_RateDeviationType rateDeviation;
};

struct StbM_PortIdType {
	uint64 clockIdentity;
	uint16 portNumber;
};

typedef uint16 StbM_SynchronizedTimeBaseType;

enum StbM_TimeBaseStatusType {
	TIMEOUT_StbM = 0x01,
	reserved = 0x02,
	SYNC_TO_GATEWAY = 0x04,
	GLOBAL_TIME_BASE = 0x08,
	TIMELEAP_FUTURE = 0x10,
	TIMELEAP_PAST = 0x20,
	RATE_CORRECTED = 0x40,
	RATE_EXCEEDED = 0x80,
	PDELAY_EXCEEDED = 0x100,
	RATEJITTERWANDER_EXCEEDED = 0x200,
	TIME_PROGRESSION_INCONSISTENCY = 0x400,
	FALLBACK_TIME_EXTRAPOLATION = 0x800
};

enum StbM_TimeBaseNotificationType {
	EV_GLOBAL_TIME = 0x01,
	EV_TIMEOUT_OCCURRED = 0x02,
	EV_TIMEOUT_REMOVED = 0x04,
	EV_TIMELEAP_FUTURE = 0x08,
	EV_TIMELEAP_FUTURE_REMOVED = 0x10,
	EV_TIMELEAP_PAST = 0x20,
	EV_TIMELEAP_PAST_REMOVED = 0x40,
	EV_SYNC_TO_SUBDOMAIN = 0x80,
	EV_SYNC_TO_GLOBAL_MASTER = 0x100,
	EV_RESYNC = 0x0200,
	EV_RATECORRECTION = 0x0400,
	EV_RATE_EXCEEDED = 0x0800,
	EV_TIME_PROGRESSION_INCONSISTENCY = 0x1000,
	EV_TIME_PROGRESSION_INCONSISTENCY_REMOVED = 0x2000,
	EV_RATEJITTERWANDER_EXCEEDED = 0x4000,
	EV_RATEJITTERWANDER_EXCEEDED_REMOVED = 0x8000,
	EV_PDELAY_EXCEEDED = 0x10000,
	EV_PDELAY_EXCEEDED_REMOVED = 0x20000,
	EV_FALLBACK_TIME_EXTRAPOLATION = 0x40000,
	EV_FALLBACK_TIME_EXTRAPOLATION_REMOVED = 0x80000
};

struct StbM_VirtualLocalTimeType {
	uint32 nanosecondsLo;
	uint32 nanosecondsHi;
};

struct StbM_TimeStampShortType {
	uint32 nanoseconds;
	uint32 seconds;
};

struct StbM_TimeStampType {
	uint32 nanoseconds;
	uint32 seconds;
	uint16 secondsHi;
};

struct StbM_TimeStampExtendedType {
	StbM_TimeBaseStatusType timeBaseStatus;
	uint32 nanoseconds;
	uint64 seconds;
};

struct StbM_TimeTupleType {
	StbM_VirtualLocalTimeType virtualLocalTime;
	StbM_TimeStampType globalTime;
	StbM_TimeBaseStatusType timeBaseStatus;
};

struct StbM_TimeTripleType {
	StbM_VirtualLocalTimeType virtualLocalTime;
	StbM_VirtualLocalTimeType fallbackVirtualLocalTime;
	StbM_TimeStampType globalTime;
	StbM_TimeBaseStatusType timeBaseStatus;
};

typedef sint32 StbM_TimeDiffType;

typedef sint16 StbM_RateDeviationType;

enum StbM_CloneConfigType {
	DEFERRED_COPY = 0x01,
	IMMEDIATE_TX = 0x02,
	APPLY_RATE = 0x04
};

struct StbM_UserDataType {
	uint8 userDataLength;
	uint8 userByte0;
	uint8 userByte1;
	uint8 userByte2;
};

typedef uint16 StbM_CustomerIdType;

struct StbM_SyncRecordTableHeadType {
	uint8 SynchronizedTimeDomain;
	uint32 HWfrequency;
	uint32 HWprescaler;
};

struct StbM_SyncRecordTableBlockType {
	uint32 GlbSeconds;
	uint32 GlbNanoSeconds;
	StbM_TimeBaseStatusType TimeBaseStatus;
	uint32 VirtualLocalTimeLow;
	StbM_RateDeviationType RateDeviation;
	uint32 LocSeconds;
	uint32 LocNanoSeconds;
	uint32 PathDelay;
	uint32 FallbackVirtualTimeLow;
};

struct StbM_OffsetRecordTableHeadType {
	uint8 OffsetTimeDomain;
};

struct StbM_OffsetRecordTableBlockType {
	uint32 GlbSeconds;
	uint32 GlbNanoSeconds;
	StbM_TimeBaseStatusType TimeBaseStatus;
};

typedef uint8 StbM_MasterConfigType;

struct StbM_EthTimeMasterMeasurementType {
	uint16 sequenceId;
	StbM_PortIdType sourcePortId;
	StbM_VirtualLocalTimeType syncEgressTimestamp;
	StbM_TimeStampShortType preciseOriginTimestamp;
	sint64 correctionField;
};

struct StbM_FrTimeMasterMeasurementType {
	uint16 sequenceCounter;
	StbM_VirtualLocalTimeType referenceTimestamp;
	StbM_TimeStampShortType preciseOriginTimestamp;
	uint8 segmentId;
	uint8 currentCycle;
	uint16 currentMacroticks;
	uint16 macrotickDuration;
	uint32 cycleLength;
};

struct StbM_CanTimeMasterMeasurementType {
	uint16 sequenceCounter;
	StbM_VirtualLocalTimeType syncEgressTimestamp;
	StbM_TimeStampShortType preciseOriginTimestamp;
	uint8 segmentId;
};

struct StbM_EthTimeSlaveMeasurementType {
	uint16 sequenceId;
	StbM_PortIdType sourcePortId;
	StbM_VirtualLocalTimeType syncIngressTimestamp;
	StbM_TimeStampShortType preciseOriginTimestamp;
	sint64 correctionField;
	uint32 pDelay;
	StbM_VirtualLocalTimeType referenceLocalTimestamp;
	StbM_TimeStampShortType referenceGlobalTimestamp;
};

struct StbM_FrTimeSlaveMeasurementType {
	uint16 sequenceCounter;
	StbM_VirtualLocalTimeType syncIngressTimestamp;
	StbM_TimeStampShortType preciseOriginTimestampSec;
	uint8 currentCycle;
	uint16 currentMacroticks;
	uint8 FCNT;
	uint16 macrotickDuration;
	uint32 cycleLength;
	StbM_VirtualLocalTimeType referenceLocalTimestamp;
	StbM_TimeStampShortType referenceGlobalTimestampSec;
	uint8 segmentId;
};

struct StbM_CanTimeSlaveMeasurementType {
	uint16 sequenceCounter;
	StbM_VirtualLocalTimeType syncIngressTimestamp;
	StbM_TimeStampShortType preciseOriginTimestamp;
	StbM_VirtualLocalTimeType referenceLocalTimestamp;
	StbM_TimeStampShortType referenceGlobalTimestamp;
	uint8 segmentId;
};

struct StbM_PdelayInitiatorMeasurementType {
	uint16 sequenceId;
	StbM_PortIdType requestPortId;
	StbM_PortIdType responsePortId;
	StbM_VirtualLocalTimeType requestOriginTimestamp;
	StbM_VirtualLocalTimeType responseReceiptTimestamp;
	StbM_TimeStampShortType requestReceiptTimestamp;
	StbM_TimeStampShortType responseOriginTimestamp;
	StbM_VirtualLocalTimeType referenceLocalTimestamp;
	StbM_TimeStampShortType referenceGlobalTimestamp;
	uint32 pdelay;
};

struct StbM_PdelayResponderMeasurementType {
	uint16 sequenceId;
	StbM_PortIdType requestPortId;
	StbM_PortIdType responsePortId;
	StbM_VirtualLocalTimeType requestReceiptTimestamp;
	StbM_VirtualLocalTimeType responseOriginTimestamp;
	StbM_VirtualLocalTimeType referenceLocalTimestamp;
	StbM_TimeStampShortType referenceGlobalTimestamp;
};

typedef uint8 StbM_TimeSyncType;

struct StbM_ProtocolParamType {
	StbM_TimeSyncType protocolType;
	sint32 cumulativeScaledRateOffset;
	uint16 gmTimeBaseIndicator;
	sint32 lastGmPhaseChange;
	uint32 scaledLastGmFreqChange;
};

typedef uint8 StbM_FreshnessArrayType[];

//[*] Extracted 40 items.

//====================================================================================================
//[*] Processing TCP/IP Stack (TcpIp) - ID: 170
struct TcpIp_ConfigType {
	implementation_specific IMPLEMENATION_SPECIFIC;
};

typedef uint16 TcpIp_DomainType;

enum TcpIp_ProtocolType {
	TCPIP_IPPROTO_TCP = 0x06,
	TCPIP_IPPROTO_UDP = 0x11
};

struct TcpIp_SockAddrType {
	TcpIp_DomainType domain;
};

struct TcpIp_SockAddrInetType {
	TcpIp_DomainType domain;
	uint16 port;
	uint32 addr[1];
};

struct TcpIp_SockAddrInet6Type {
	TcpIp_DomainType domain;
	uint16 port;
	uint32 addr[4];
};

typedef uint8 TcpIp_LocalAddrIdType;

typedef uint16 TcpIp_SocketIdType;

enum TcpIp_StateType {
	TCPIP_STATE_ONLINE,
	TCPIP_STATE_ONHOLD,
	TCPIP_STATE_OFFLINE,
	TCPIP_STATE_STARTUP,
	TCPIP_STATE_SHUTDOWN
};

enum TcpIp_IpAddrStateType {
	TCPIP_IPADDR_STATE_ASSIGNED,
	TCPIP_IPADDR_STATE_ONHOLD,
	TCPIP_IPADDR_STATE_UNASSIGNED
};

enum TcpIp_EventType {
	TCPIP_TCP_RESET = 0x01,
	TCPIP_TCP_CLOSED = 0x02,
	TCPIP_TCP_FIN_RECEIVED = 0x03,
	TCPIP_UDP_CLOSED = 0x04,
	TCPIP_TLS_HANDSHAKE_SUCCEEDED = 0x05
};

enum TcpIp_IpAddrAssignmentType {
	TCPIP_IPADDR_ASSIGNMENT_STATIC,
	TCPIP_IPADDR_ASSIGNMENT_LINKLOCAL_DOIP,
	TCPIP_IPADDR_ASSIGNMENT_DHCP,
	TCPIP_IPADDR_ASSIGNMENT_LINKLOCAL,
	TCPIP_IPADDR_ASSIGNMENT_IPV6_ROUTER,
	TCPIP_IPADDR_ASSIGNMENT_ALL
};

enum TcpIp_ReturnType {
	TCPIP_E_OK,
	TCPIP_E_NOT_OK,
	TCPIP_E_PHYS_ADDR_MISS,
	TCPIP_E_PENDING
};

typedef uint8 TcpIp_ParamIdType;

struct TcpIp_ArpCacheEntryType {
	uint32 InetAddr[1];
	uint8 PhysAddr[6];
	uint8 State;
};

struct TcpIp_NdpCacheEntryType {
	uint32 Inet6Addr[4];
	uint8 PhysAddr[6];
	uint8 State;
};

typedef uint8 TcpIp_MeasurementIdxType;

typedef uint16 TcpIp_TlsConnectionIdType;

typedef uint32 TCPIP_IPADDR_ANY;

typedef uint32 TCPIP_IP6ADDR_ANY;

typedef uint16 TCPIP_PORT_ANY;

typedef TcpIp_LocalAddrIdType TCPIP_LOCALADDRID_ANY;

//[*] Extracted 32 items.

//====================================================================================================
//[*] Processing Time Service (Tm) - ID: 14
struct Tm_PredefTimer1us16bitType {
	implementation_specific IMPLEMENATION_SPECIFIC;
};

struct Tm_PredefTimer1us24bitType {
	implementation_specific IMPLEMENATION_SPECIFIC;
};

struct Tm_PredefTimer1us32bitType {
	implementation_specific IMPLEMENATION_SPECIFIC;
};

struct Tm_PredefTimer100us32bitType {
	implementation_specific IMPLEMENATION_SPECIFIC;
};

//[*] Extracted 20 items.

//====================================================================================================
//[*] Processing Time Sync Over CAN (CanTSyn) - ID: 161
struct CanTSyn_ConfigType {
	implementation_specific IMPLEMENATION_SPECIFIC;
};

enum CanTSyn_TransmissionModeType {
	CANTSYN_TX_OFF,
	CANTSYN_TX_ON
};

//[*] Extracted 8 items.

//====================================================================================================
//[*] Processing Time Sync Over Ethernet (EthTSyn) - ID: 164
struct EthTSyn_ConfigType {
	implementation_specific IMPLEMENATION_SPECIFIC;
};

enum EthTSyn_TransmissionModeType {
	ETHTSYN_TX_OFF = 0x00,
	ETHTSYN_TX_ON = 0x01
};

//[*] Extracted 11 items.

//====================================================================================================
//[*] Processing Time Sync Over FlexRay (FrTSyn) - ID: 163
struct FrTSyn_ConfigType {
	implementation_specific IMPLEMENATION_SPECIFIC;
};

enum FrTSyn_TransmissionModeType {
	FRTSYN_TX_OFF,
	FRTSYN_TX_ON
};

//[*] Extracted 8 items.

//====================================================================================================
//[*] Processing TTCAN Driver (Ttcan) - ID: 84
typedef uint16 Can_TTTimeType;

enum Can_TTMasterSlaveModeType {
	CAN_TT_BACKUP_MASTER,
	CAN_TT_CURRENT_MASTER,
	CAN_TT_MASTER_OFF,
	CAN_TT_SLAVE
};

enum Can_TTSyncModeEnumType {
	CAN_TT_IN_GAP,
	CAN_TT_IN_SCHEDULE,
	CAN_TT_SYNC_OFF,
	CAN_TT_SYNCHRONIZING
};

struct Can_TTMasterStateType {
	Can_TTMasterSlaveModeType masterSlaveMode;
	uint8 refTriggerOffset;
	Can_TTSyncModeEnumType syncMode;
};

enum Can_TTErrorLevelEnumType {
	CAN_TT_ERROR_S0,
	CAN_TT_ERROR_S1,
	CAN_TT_ERROR_S2,
	CAN_TT_ERROR_S3
};

struct Can_TTErrorLevelType {
	Can_TTErrorLevelEnumType errorLevel;
	uint8 maxMessageStatusCount;
	uint8 minMessageStatusCount;
};

enum Can_TTTimeSourceType {
	CAN_TT_CYCLE_TIME,
	CAN_TT_GLOBAL_TIME,
	CAN_TT_LOCAL_TIME,
	CAN_TT_UNDEFINED
};

typedef uint16 Can_TTTURType;

//[*] Extracted 19 items.

//====================================================================================================
//[*] Processing TTCAN Interface (TtcanIf) - ID: 66
typedef uint16 CanIf_TTTimeType;

enum CanIf_TTMasterSlaveModeType {
	CANIF_TT_BACKUP_MASTER,
	CANIF_TT_CURRENT_MASTER,
	CANIF_TT_MASTER_OFF,
	CANIF_TT_SLAVE
};

enum CanIf_TTSyncModeEnumType {
	CANIF_TT_IN_GAP,
	CANIF_TT_IN_SCHEDULE,
	CANIF_TT_SYNC_OFF,
	CANIF_TT_SYNCHRONIZING
};

struct CanIf_TTMasterStateType {
	CanIf_TTMasterSlaveModeType masterSlaveMode;
	uint8 refTriggerOffset;
	CanIf_TTSyncModeEnumType syncMode;
};

enum CanIf_TTErrorLevelEnumType {
	CANIF_TT_ERROR_S0,
	CANIF_TT_ERROR_S1,
	CANIF_TT_ERROR_S2,
	CANIF_TT_ERROR_S3
};

struct CanIf_TTErrorLevelType {
	CanIf_TTErrorLevelEnumType errorLevel;
	uint8 maxMessageStatusCount;
	uint8 minMessageStatusCount;
};

enum CanIf_TTSevereErrorEnumType {
	CANIF_TT_CONFIG_ERROR,
	CANIF_TT_WATCH_TRIGGER_REACHED,
	CANIF_TT_APPL_WATCHDOG
};

enum CanIf_TTTimeSourceType {
	CANIF_TT_CYCLE_TIME,
	CANIF_TT_GLOBAL_TIME,
	CANIF_TT_LOCAL_TIME,
	CANIF_TT_UNDEFINED
};

enum CanIf_TTEventEnumType {
	CANIF_TT_ERROR_LEVEL_CHANGED,
	CANIF_TT_INIT_WATCH_TRIGGER,
	CANIF_TT_NO_ERROR,
	CANIF_TT_SYNC_FAILED,
	CANIF_TT_TX_OVERFLOW,
	CANIF_TT_TX_UNDERFLOW
};

struct CanIf_TTTimingErrorIRQType {
	CanIf_TTErrorLevelType errorLevel;
	CanIf_TTEventEnumType event;
};

//[*] Extracted 25 items.

//====================================================================================================
//[*] Processing UDP Network Management (UdpNm) - ID: 33
struct UdpNm_ConfigType {
	implementation_specific IMPLEMENATION_SPECIFIC;
};

enum UdpNm_PduPositionType {
	UDPNM_PDU_BYTE_0 = 0x00,
	UDPNM_PDU_BYTE_1 = 0x01,
	UDPNM_PDU_OFF = 0xFF
};

//[*] Extracted 26 items.

//====================================================================================================
//[*] Processing V2X Data Manager (V2xDM) - ID: 186
struct V2xDm_Rep_Stack_Msg_Type {
	implementation_specific IMPLEMENATION_SPECIFIC;
};

//[*] Extracted 5 items.

//====================================================================================================
//[*] Processing Vehicle-2-X Basic Transport (V2xBtp) - ID: 183

enum V2x_GnTxResultType {
	V2X_GNTX_ACCEPTED,
	V2X_GNTX_E_MAXSDUSIZEOVFL,
	V2X_GNTX_E_MAXPACKETLIFETIME,
	V2X_GNTX_E_TCID,
	V2X_GNTX_E_MAXGEOAREASIZE,
	V2X_GNTX_E_UNSPECIFIED
};

enum V2x_SecProfileType {
	V2X_SECPROF_CAM,
	V2X_SECPROF_DENM,
	V2X_SECPROF_OTHER_SIGNED,
	V2X_SECPROF_OTHER_SIGNED_EXTERNAL,
	V2X_SECPROF_OTHER_SIGNED_ENCRYPTED
};

enum V2x_SecReturnType {
	V2X_E_OK,
	V2X_E_NOT_OK,
	V2X_E_UNVERIFIED,
	V2X_E_BUF_OVFL
};

typedef uint16 V2x_MaximumPacketLifetimeType;

typedef uint8 V2x_TrafficClassIdType;

enum V2x_ChanType {
	V2X_SCH4 = 172,
	V2X_SCH3 = 174,
	V2X_SCH1 = 176,
	V2X_SCH2 = 178,
	V2X_CCH = 180
};

enum V2x_GnUpperProtocolType {
	V2X_ANY,
	V2X_BTPA,
	V2X_BTPB,
	V2X_IPV6
};

enum V2x_GnPacketTransportType {
	V2X_GN_GEOUNICAST = 0x00,
	V2X_GN_GEOANYCAST = 0x01,
	V2X_GN_GEOBROADCAST = 0x02,
	V2X_GN_TSB = 0x03,
	V2X_GN_SHB = 0x04
};

enum V2x_GnDestinationType {
	V2X_GN_DESTINATION_ADDRESS = 0x00,
	V2X_GN_DESTINATION_AREA = 0x01
};

typedef uint64 V2x_GnAddressType;

enum V2x_GnAreaShapeType {
	V2X_GN_SHAPE_CIRCLE = 0x00,
	V2X_GN_SHAPE_RECT = 0x01,
	V2X_GN_SHAPE_ELLIPSE = 0x02
};

struct V2x_GnDestinationAreaType {
	sint32 latitude;
	sint32 longitude;
	uint16 distanceA;
	uint16 distanceB;
	uint16 angle;
	V2x_GnAreaShapeType shape;
};

struct V2x_GnLongPositionVectorType {
	V2x_GnAddressType gnAddress;
	uint32 timestamp;
	sint32 latitude;
	sint32 longitude;
	boolean pai;
	sint16 speed;
	uint16 heading;
};

typedef uint64 V2x_PseudonymType;

typedef uint8 V2x_SecReportType;

struct V2xBtp_TxParamsType {
	V2x_GnUpperProtocolType upperProtocol;
	uint16 destinationPort;
	V2x_GnPacketTransportType transportType;
	V2x_GnAddressType destinationAddress;
	V2x_GnDestinationAreaType destinationArea;
	V2x_GnDestinationType destinationType;
	V2x_SecProfileType secProfile;
	uint16 maxPacketLifetime;
	V2x_TrafficClassIdType trafficClassId;
};

struct V2xBtp_RxParamsType {
	V2x_GnUpperProtocolType upperProtocol;
	V2x_GnPacketTransportType packetTransportType;
	V2x_GnAddressType destinationAddress;
	V2x_GnDestinationAreaType destinationArea;
	V2x_GnDestinationType destinationType;
	V2x_GnLongPositionVectorType sourcePositionVector;
	V2x_SecReportType securityReport;
	uint64 certificateId;
	uint8 sspBits[4];
	uint8 sspLength;
	V2x_TrafficClassIdType trafficClass;
	uint16 remPacketLifetime;
	uint8 remHopLimit;
	uint32 itsAid;
};

//[*] Extracted 5 items.

//====================================================================================================
//[*] Processing Vehicle-2-X Facilities (V2xFac) - ID: 184
struct V2xFac_RxParamsType {
	uint16 destinationPort;
	V2x_GnAddressType destinationAddress;
	V2x_GnDestinationAreaType destinationArea;
	V2x_GnDestinationType destinationType;
	V2x_GnLongPositionVectorType sourcePositionVector;
	V2x_SecReportType securityReport;
	uint64 certificateId;
	uint8 sspBits[4];
	uint8 sspLength;
	V2x_TrafficClassIdType trafficClass;
	uint16 remPacketLifetime;
	uint32 itsAid;
};

//[*] Extracted 11 items.

//====================================================================================================
//[*] Processing Vehicle-2-X GeoNetworking (V2xGn) - ID: 182
struct V2xGn_TxParamsType {
	V2x_GnUpperProtocolType upperProtocol;
	V2x_GnPacketTransportType transportType;
	V2x_GnAddressType destinationAddress;
	V2x_GnDestinationAreaType destinationArea;
	V2x_GnDestinationType destinationType;
	V2x_SecProfileType secProfile;
	uint16 maxPacketLifetime;
	V2x_TrafficClassIdType trafficClassId;
};

//[*] Extracted 10 items.

//====================================================================================================
//[*] Processing Vehicle-2-X Management (V2xM) - ID: 185
struct V2xM_ConfigType {
	implementation_specific IMPLEMENATION_SPECIFIC;
};




//[*] Extracted 19 items.
//====================================================================================================
//[*] Processing Chinese Vehicle-2-X Management (CnV2xM) - ID: 193
struct CnV2xM_ConfigType {
	V2xM_ConfigType implementationspecific;
};

enum CnV2xM_ChanType {
	CN_V2X_CH1
};

//====================================================================================================
//[*] Processing Watchdog Driver (Wdg) - ID: 102
struct Wdg_ConfigType {
	implementation_specific IMPLEMENATION_SPECIFIC;
};

//[*] Extracted 4 items.

//====================================================================================================
//[*] Processing Watchdog Interface (WdgIf) - ID: 43
enum WdgIf_ModeType {
	WDGIF_OFF_MODE,
	WDGIF_SLOW_MODE,
	WDGIF_FAST_MODE
};

//[*] Extracted 3 items.

//====================================================================================================
//[*] Processing Watchdog Manager (WdgM) - ID: 13
struct WdgM_ConfigType {
	implementation_specific IMPLEMENATION_SPECIFIC;
};

typedef uint8 WdgM_ModeType;

enum WdgM_GlobalStatusType {
	WDGM_GLOBAL_STATUS_OK = 0x00,
	WDGM_GLOBAL_STATUS_FAILED = 0x01,
	WDGM_GLOBAL_STATUS_EXPIRED = 0x02,
	WDGM_GLOBAL_STATUS_STOPPED = 0x03,
	WDGM_GLOBAL_STATUS_DEACTIVATED = 0x04
};

enum WdgM_LocalStatusType {
	WDGM_LOCAL_STATUS_OK = 0x00,
	WDGM_LOCAL_STATUS_FAILED = 0x01,
	WDGM_LOCAL_STATUS_EXPIRED = 0x02,
	WDGM_LOCAL_STATUS_DEACTIVATED = 0x04
};

enum WdgM_Mode {
	SUPERVISION_OK = 0x00,
	SUPERVISION_FAILED = 0x01,
	SUPERVISION_EXPIRED = 0x02,
	SUPERVISION_STOPPED = 0x03,
	SUPERVISION_DEACTIVATED = 0x04
};

typedef uint16 WdgM_SupervisedEntityIdType;
typedef uint16 WdgM_CheckpointIdType;


//[*] Extracted 11 items.

//====================================================================================================
//[*] Processing Wireless Ethernet Driver (WEth) - ID: 87
struct WEth_ConfigType {
	implementation_specific IMPLEMENATION_SPECIFIC;
};

enum WEth_BufWRxParamIdType {
	WETH_BUFWRXPID_RSSI = 0x00,
	WETH_BUFWRXPID_CHANNEL_ID = 0x01,
	WETH_BUFWRXPID_FREQ = 0x02,
	WETH_BUFWRXPID_ANTENNA_ID = 0x04
};

enum WEth_BufWTxParamIdType {
	WETH_BUFWTXPID_POWER = 0x00,
	WETH_BUFWTXPID_CHANNEL_ID = 0x01,
	WETH_BUFWTXPID_QUEUE_ID = 0x02,
	WETH_BUFWTXPID_ANTENNA_ID = 0x04
};

//[*] Extracted 20 items.

//====================================================================================================
//[*] Processing Wireless Ethernet TransceiverDriver (WEthTrcv) - ID: 74
struct WEthTrcv_ConfigType {
	implementation_specific IMPLEMENATION_SPECIFIC;
};

enum WEthTrcv_SetRadioParamIdType {
	WETHTRCV_SETRADIOPID_SEL_TRCV_CHCFG = 0x01,
	WETHTRCV_SETRADIOPID_SET_CHCFGID = 0x02,
	WETHTRCV_SETRADIOPID_TOLLINGZONE_INFO = 0x03
};

enum WEthTrcv_SetChanRxParamIdType {
	WETHTRCV_SETCHRXPID_BITRATE = 0x00,
	WETHTRCV_SETCHRXPID_BANDWIDTH = 0x01,
	WETHTRCV_SETCHRXPID_FREQ = 0x02,
	WETHTRCV_SETCHRXPID_CSPWRTRESH = 0x03,
	WETHTRCV_SETCHRXPID_RADIO_MODE = 0x04,
	WETHTRCV_SETCHRXPID_ANTENNA = 0x05
};

enum WEthTrcv_SetChanTxParamIdType {
	WETHTRCV_SETCHTXPID_BITRATE = 0x00,
	WETHTRCV_SETCHTXPID_BANDWIDTH = 0x01,
	WETHTRCV_SETCHTXPID_TXPOWER = 0x02,
	WETHTRCV_SETCHTXPID_DCC_CBR = 0x03,
	WETHTRCV_SETCHTXPID_TXQSEL = 0x04,
	WETHTRCV_SETCHTXPID_TXQCFG_AIFSN = 0x05,
	WETHTRCV_SETCHTXPID_TXQCFG_CWMIN = 0x06,
	WETHTRCV_SETCHTXPID_TXQCFG_CWMAX = 0x07,
	WETHTRCV_SETCHTXPID_TXQCFG_TXOP = 0x08,
	WETHTRCV_SETCHTXPID_RADIO_MODE = 0x09,
	WETHTRCV_SETCHTXPID_ANTENNA = 0x0A,
	WETHTRCV_SETCHTXPID_PACKET_INTERVAL = 0x0C,
	WETHTRCV_SETCHTXPID_DCC_STATE = 0x0D
};

enum WEthTrcv_GetChanRxParamIdType {
	WETHTRCV_GETCHRXPID_CBR = 0x00,
	WETHTRCV_GETCHRXPID_CIT = 0x01
};

typedef uint32 WEthTrcv_BandwidthType;

typedef uint16 WEthTrcv_TxPwrLvlType;

typedef uint16 WEthTrcv_RssiType;

typedef uint8 WEthTrcv_RadioModeType;

//[*] Extracted 10 items.

//====================================================================================================
//[*] Processing XCP (Xcp) - ID: 212
struct Xcp_ConfigType {
	implementation_specific IMPLEMENATION_SPECIFIC;
};

enum Xcp_TransmissionModeType {
	XCP_TX_OFF = 0x00,
	XCP_TX_ON = 0x01
};

//[*] Extracted 7 items.
