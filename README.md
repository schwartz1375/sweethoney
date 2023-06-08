# Sweethoney
Sweethoney is a file triaging tool.  The tool parses out the following information:

* PE header information
* Lists functions declared and referenced
* Lists exported symbols
* Calculates file statics
* Alerts on suspicious IAT - This is a static list, and it maybe need to be tuned for your use case!
* Alerts on suspicious sections with extremely low (less than 1) & high (greater than 7) entorpy

## Additional Resources
* [Pev Tools](https://github.com/merces/pev) (i.e. pestr, pescan, etc.)
* [Peframe](https://github.com/merces/pev)
* [Pestudio](https://www.winitor.com/)
* [Go Reverse Engineering Tool Kit](https://go-re.tk/)

