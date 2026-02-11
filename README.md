# Saleae SDIO Analyzer

## Supported Decoding

- CMD (command + response) framing with CRC7 check
- DAT data phase in 1-bit (DAT0) or 4-bit (DAT0..DAT3) mode
- Data table entries for each DAT byte (Type = `DATA`)

## Build

### Linux

```
cmake -H. -Bbuild -DCMAKE_INSTALL_PREFIX=$HOME/.local/share/saleae -GNinja
ninja -C build install
```

## Usage

1. [Import custom analyzers](https://support.saleae.com/faq/technical-faq/setting-up-developer-directory)
2. Add the SDIO analyzer and assign channels:
   - `Clock` and `Command` are required.
   - `DAT0` enables 1-bit data decoding.
   - `DAT1..DAT3` must be all set (with `DAT0`) to enable 4-bit data decoding.
3. Set the display base to Hex if you want hex bytes in bubbles and the data table.

### Data Table

- DAT bytes appear as separate rows with Type `DATA`.
- The table includes `DATA` (byte value) and `WIDTH` (1 or 4).
- CMD52/CMD53 rows include a `PARSING` column with decoded fields (e.g., `WRITE | FUNC=0 | RAW=0 | ADDR=0x210 | DATA=0x80`).
- RESP52/RESP53 rows include R5 decoding (STATE/FN/DATA plus asserted flags like `COM_CRC_ERROR`, `ILLEGAL_COMMAND`, `ERROR`, `OUT_OF_RANGE`).
- Additional command/response parsing is included for CMD0/3/5/7/8/11/12/13/16/59 and their standard response types (R1/R4/R6/R7).

### Notes

- Data length is inferred for CMD53 (IO_RW_EXTENDED) using the command argument as a best-effort guess.
