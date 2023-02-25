https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/creating-an-inf-file-for-a-minifilter-driver

[classGuid]
https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/file-system-filter-driver-classes-and-class-guids

[altitudes]
https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/allocated-altitudes

[loadordergroup]
https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/load-order-groups-for-file-system-filter-drivers

Registry INFORMATION
https://m.blog.naver.com/rlfmalehd/220749232200

modifiy .inf
Class       = "AntiVirus"                         ;This is determined by the work this filter driver does
ClassGuid   = {b1d1a169-c54f-4379-81db-bee7d88d7454}    ;This value is determined by the Load Order Group value
LoadOrderGroup = "FSFilter Anti-Virus"
Instance1.Altitude       = "329998"