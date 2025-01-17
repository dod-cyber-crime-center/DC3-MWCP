rule GenericVTwoRule
{
	meta:
		description = "Generic password parser version two"
		author = "FH"
		data = "2025-01-17"
		version = "1.0"
		mwcp = "GenericVTwo"

	strings:
		$regex = /username:[^\n]*\npassword:[^\n]*\nwebsite:[^\n]*[\n$]/
	condition:
		any of them
}
rule GenericVOneRule
{
	meta:
		description = "Generic password parser version one"
		author = "FH"
		data = "2025-01-17"
		version = "1.0"
		mwcp = "GenericVOne"

	strings:
		$regex = /URL:[^\n]*\n\s+Username:[^\n]*\n\s+Password:[^\n]*[\n$]/
	condition:
		any of them
}
rule AzVOne
{
	meta:
		description = "Az version one"
		author = "FH"
		data = "2025-01-17"
		version = "1.0"
		mwcp = "AzVOne"
	strings:
		$regex = /SOFT:[^\n]*\nURL:[^\n]*\nUSER:[^\n]*\nPASS:[^\n]*[\n$]/
	condition:
		any of them
}

