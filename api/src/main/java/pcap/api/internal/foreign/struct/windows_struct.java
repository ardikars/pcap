package pcap.api.internal.foreign.struct;

import java.foreign.annotations.NativeGetter;
import java.foreign.annotations.NativeStruct;
import java.foreign.memory.Array;
import java.foreign.memory.Pointer;
import java.foreign.memory.Struct;

public interface windows_struct {

  @NativeStruct("[u16(sa_family)[14u8](sa_data)](sockaddr)")
  interface sockaddr extends Struct<sockaddr> {

    @NativeGetter("sa_family")
    short sa_family$get();

    @NativeGetter("sa_data")
    Array<Byte> sa_data$get();
  }

  @NativeStruct("[u8(s_b1)u8(s_b2)u8(s_b3)u8(s_b4)](anon$inaddr_h$391)")
  interface anon$S_un_b extends Struct<anon$S_un_b> {

    @NativeGetter("s_b1")
    byte s_b1$get();

    @NativeGetter("s_b2")
    byte s_b2$get();

    @NativeGetter("s_b3")
    byte s_b3$get();

    @NativeGetter("s_b4")
    byte s_b4$get();
  }

  @NativeStruct(
      "[${anon$inaddr_h$391}(S_un_b)|${anon$inaddr_h$446}(S_un_w)|u32(S_addr)](anon$inaddr_h$379)")
  interface anon$S_un extends Struct<anon$S_un> {

    @NativeGetter("S_un_b")
    anon$S_un_b S_un_b$get();

    @NativeGetter("S_un_w")
    anon$S_un_w S_un_w$get();

    @NativeGetter("S_addr")
    int S_addr$get();
  }

  @NativeStruct("[u16(s_w1)u16(s_w2)](anon$inaddr_h$446)")
  interface anon$S_un_w extends Struct<anon$S_un_w> {

    @NativeGetter("s_w1")
    short s_w1$get();

    @NativeGetter("s_w2")
    short s_w2$get();
  }

  @NativeStruct("[${anon$inaddr_h$379}(S_un)](in_addr)")
  interface in_addr extends Struct<in_addr> {

    @NativeGetter("S_un")
    anon$S_un S_un$get();
  }

  @NativeStruct(
      value = "[u16(sin_family)u16(sin_port)${in_addr}(sin_addr)[8u8](sin_zero)](sockaddr_in)",
      resolutionContext = in_addr.class)
  interface sockaddr_in extends Struct<sockaddr_in> {

    @NativeGetter("sin_family")
    short sin_family$get();

    @NativeGetter("sin_port")
    short sin_port$get();

    @NativeGetter("sin_addr")
    in_addr sin_addr$get();

    @NativeGetter("sin_zero")
    Array<Byte> sin_zero$get();
  }

  @NativeStruct(value = "[${anon$u}(u)](in6_addr)", resolutionContext = in6_addr.anon$u.class)
  interface in6_addr extends Struct<in6_addr> {

    @NativeGetter("u")
    anon$u u$get();

    @NativeStruct("[[16u8](Byte)[8u16](Word)](anon$u)")
    interface anon$u extends Struct<anon$u> {

      @NativeGetter("Byte")
      Array<Byte> Byte$get();

      @NativeGetter("Word")
      Array<Short> Word$get();
    }
  }

  @NativeStruct(
      value =
          "[u16(sin6_family)u16(sin6_port)u32(sin6_flowinfo)${in6_addr}(sin6_addr)u32(sin6_scope_id)](sockaddr_in6)",
      resolutionContext = in6_addr.class)
  interface sockaddr_in6 extends Struct<sockaddr_in6> {

    @NativeGetter("sin6_family")
    short sin6_family$get();

    @NativeGetter("sin6_port")
    short sin6_port$get();

    @NativeGetter("sin6_flowinfo")
    int sin6_flowinfo$get();

    @NativeGetter("sin6_addr")
    in6_addr sin6_addr$get();

    @NativeGetter("sin6_scope_id")
    int sin6_scope_id$get();
  }

  @NativeStruct("[[16u8](String)](IP_ADDRESS_STRING)")
  interface IP_ADDRESS_STRING extends Struct<IP_ADDRESS_STRING> {
    @NativeGetter("String")
    Array<Byte> String$get();
  }

  @NativeStruct(
      "[u64(Next):${_IP_ADDR_STRING}${IP_ADDRESS_STRING}(IpAddress)${IP_ADDRESS_STRING}(IpMask)i16(Context)x48](_IP_ADDR_STRING)")
  interface _IP_ADDR_STRING extends Struct<_IP_ADDR_STRING> {

    @NativeGetter("Next")
    Pointer<_IP_ADDR_STRING> Next$get();

    @NativeGetter("IpAddress")
    IP_ADDRESS_STRING IpAddress$get();

    @NativeGetter("IpMask")
    IP_ADDRESS_STRING IpMask$get();

    @NativeGetter("Context")
    short Context$get();
  }

  @NativeStruct(
      "[u64(Next):${_IP_ADAPTER_INFO}i16(ComboIndex)[260u8](AdapterName)[132u8](Description)x16u32(AddressLength)[8u8](Address)i16(Index)x16u32(Type)u32(DhcpEnabled)x32u64(CurrentIpAddress):${_IP_ADDR_STRING}${_IP_ADDR_STRING}(IpAddressList)${_IP_ADDR_STRING}(GatewayList)${_IP_ADDR_STRING}(DhcpServer)i32(HaveWins)x32${_IP_ADDR_STRING}(PrimaryWinsServer)${_IP_ADDR_STRING}(SecondaryWinsServer)i64(LeaseObtained)i64(LeaseExpires)](_IP_ADAPTER_INFO)")
  interface _IP_ADAPTER_INFO extends Struct<_IP_ADAPTER_INFO> {

    @NativeGetter("Next")
    Pointer<_IP_ADAPTER_INFO> Next$get();

    @NativeGetter("ComboIndex")
    short ComboIndex$get();

    @NativeGetter("AdapterName")
    Array<Byte> AdapterName$get();

    @NativeGetter("Description")
    Array<Byte> Description$get();

    @NativeGetter("AddressLength")
    int AddressLength$get();

    @NativeGetter("Address")
    Array<Byte> Address$get();

    @NativeGetter("Index")
    short Index$get();

    @NativeGetter("Type")
    int Type$get();

    @NativeGetter("DhcpEnabled")
    int DhcpEnabled$get();

    @NativeGetter("CurrentIpAddress")
    Pointer<_IP_ADDR_STRING> CurrentIpAddress$get();

    @NativeGetter("IpAddressList")
    _IP_ADDR_STRING IpAddressList$get();

    @NativeGetter("GatewayList")
    _IP_ADDR_STRING GatewayList$get();

    @NativeGetter("DhcpServer")
    _IP_ADDR_STRING DhcpServer$get();

    @NativeGetter("HaveWins")
    int HaveWins$get();

    @NativeGetter("PrimaryWinsServer")
    _IP_ADDR_STRING PrimaryWinsServer$get();

    @NativeGetter("SecondaryWinsServer")
    _IP_ADDR_STRING SecondaryWinsServer$get();

    @NativeGetter("LeaseObtained")
    long LeaseObtained$get();

    @NativeGetter("LeaseExpires")
    long LeaseExpires$get();
  }
}
