import "pe"
 
rule code_certificate_serial_match : certificate 
{
    meta:
        description = "Detects PE files signed using a certificate assigned to Sysprint AG"
    condition:
        uint16be(0) == 0x4d5a and
        pe.number_of_signatures >= 1 and
        for any s in (0..pe.number_of_signatures - 1): (
        pe.signatures[s].serial == "00:c0:a3:9e:33:ec:8b:ea:47:72:de:4b:dc:b7:49:bb:95" )
}
