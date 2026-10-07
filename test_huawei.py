"""Tests for Huawei OceanStor CIFS audit XML parsing."""
import netapp_audit_viewer as v

OPEN = (b"<Event xmlns='http://schemas.huawei.com/events/audit-event'><System>"
        b"<Provider Name='Huawei-Security-Auditing' Guid='{x}'/><EventID>4656</EventID>"
        b"<EventName>Open Object</EventName><Source>CIFS</Source><Result>Audit Success</Result>"
        b"<TimeCreated SystemTime='2026-09-30T20:59:53.408261000Z'/>"
        b"<Computer>TB34HUAWEISTR/NAS_CIFS_vStore</Computer></System><EventData>"
        b"<Data Name='SubjectIP' IPVersion='4'>10.30.1.153</Data>"
        b"<Data Name='SubjectUnix' Local='true' Gid='65534' Uid='65534'/>"
        b"<Data Name='SubjectDomainName'>TOMBANK</Data><Data Name='SubjectUserName'>suboa</Data>"
        b"<Data Name='ObjectType'>File</Data>"
        b"<Data Name='ObjectName'>(BOAFiles02);/BOA/a.pdf</Data>"
        b"<Data Name='AccessList'>%%4416 %%4423 </Data>"
        b"<Data Name='DesiredAccess'></Data></EventData></Event>")

LOGON = (b"<Event xmlns='http://schemas.huawei.com/events/audit-event'><System>"
         b"<Provider Name='Huawei-Security-Auditing'/><EventID>4624</EventID>"
         b"<EventName>Logon Attempt</EventName><Result>Audit Success</Result>"
         b"<TimeCreated SystemTime='2026-09-30T20:59:53.401769000Z'/></System><EventData>"
         b"<Data Name='IpAddress' IPVersion='4'>10.30.1.153</Data>"
         b"<Data Name='TargetUserName'>suboa</Data><Data Name='TargetDomainName'>TOMBANK</Data>"
         b"<Data Name='LogonType'>3</Data></EventData></Event>")


def test_huawei_open():
    e = v.parse_event(OPEN)
    assert e["Vendor"] == "Huawei"
    assert (e["User"], e["IP"], e["Domain"]) == ("suboa", "10.30.1.153", "TOMBANK")
    assert e["Share"] == "BOAFiles02" and e["Path"] == "/BOA/a.pdf"
    assert e["Action"] == "ReadData/ListDirectory; ReadAttributes"
    assert e["_extra"]["SubjectUnix"] == "Local=true, Gid=65534, Uid=65534"


def test_huawei_logon():
    e = v.parse_event(LOGON)
    assert e["Vendor"] == "Huawei" and e["User"] == "suboa"
    assert e["IP"] == "10.30.1.153" and e["Action"] == "LogonType 3"


def test_event_regex_with_wrapper():
    data = b'<?xml version="1.0"?>\n<Events>\n' + OPEN + b"\n" + LOGON + b"\n</Events>"
    assert len(list(v.EVENT_RE.finditer(data))) == 2


def test_netapp_still_works():
    e = v.parse_event(b"<Event><System><EventID>4625</EventID><Result>Audit Failure</Result>"
                      b"</System><EventData><Data Name='IpAddress'>1.2.3.4</Data>"
                      b"<Data Name='TargetUserName'>u</Data></EventData></Event>")
    assert e["Vendor"] == "NetApp" and e["User"] == "u" and e["IP"] == "1.2.3.4"


def test_bare_ampersand_and_unknown_fields():
    ev = OPEN.replace(b"/BOA/a.pdf", b"/BOA/A & B.pdf").replace(
        b"<EventData>", b"<EventData><Data Name='NewField'>x</Data>")
    ev = ev.replace(b"</System>", b"<Extra>y</Extra></System>")
    e = v.parse_event(ev)
    assert e and e["Path"] == "/BOA/A & B.pdf"
    assert e["_extra"]["NewField"] == "x" and e["_extra"]["Extra"] == "y"


def test_non_utf8_bytes():
    e = v.parse_event(OPEN.replace(b"a.pdf", "ş.pdf".encode("cp1254")))
    assert e and e["Path"].endswith(".pdf")
