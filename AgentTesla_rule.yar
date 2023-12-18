rule AgentTesla_Mana_Campaign {
    meta:
      	author = "HomardBoy"
        description = "AgentTesla version 3 linked to the 2021 Gorgon group APT campaign"
    strings:
        $str1 = "get_enableLog" ascii
        $str2 = "get_Browser" ascii
        $str3 = "get_kbok" ascii
        $str4 = "get_Ctrl" ascii
        $str5 = "get_Shift" ascii
        $str6 = "get_Alt" ascii
        $str7 = "get_CHoo" ascii
        $str8 = "tor" ascii
	$str9 = "mscoree.dll" ascii
    condition:
        (uint16(0) == 0x5a4d and all of ($str*))
}