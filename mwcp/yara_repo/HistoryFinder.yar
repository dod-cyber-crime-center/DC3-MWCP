rule GenericVOneRule
{
	meta:
		description = "Generic Yara rule to detect browser history  data"
		author = "FH"
		date = "2025-01-27"
		version = "1.0"
		mwcp = "HistoryFinder.GenericVOne"

	strings:
		$title = "Title:" ascii wide
		$url = "URL:" ascii wide
		$visit = "Visit Count:" ascii wide

	condition:
		all of them
}
