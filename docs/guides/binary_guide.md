# Binary Analysis Guide

## Basic Commands

### 1. Open File
- Command: `open`
- Usage: Enter the path to the binary file
- Supports: ELF, PE, Mach-O, etc.

### 2. Analysis
- Command: `analyze`
- Performs full analysis of the binary
- Identifies functions, strings, references
- Required before most other commands

### 3. Information
- Command: `info`
- Shows basic file information
- Format, architecture, entry points
- Sections and segments

### 4. Functions
- Command: `funcs`
- Lists all identified functions
- Shows address, size, name
- Includes both known and unknown functions

### 5. Strings
- Command: `strings`
- Finds all strings in the binary
- Shows address and content
- Useful for identifying hardcoded values

### 6. Disassembly
- Command: `disasm [function_name]`
- Disassembles specified function
- Shows assembly code with annotations
- Leave function name empty for current position

### 7. Pattern Search
- Command: `search <pattern>`
- Searches for hex patterns
- Example: search "90 90 90" for NOP slides
- Supports regular expressions

### 8. References
- Command: `refs <function_name>`
- Finds cross-references to function
- Shows where function is called
- Helps understand code flow

### 9. Interactive Shell
- Command: `shell`
- Opens interactive radare2 shell
- Full access to r2 commands
- For advanced analysis

## Tips
- Always run `analyze` after opening a new file
- Use `info` to verify file type and architecture
- Check `strings` for interesting information
- Use `shell` for advanced r2 features

## Best Practices
1. Start with basic analysis
2. Look for interesting strings
3. Identify key functions
4. Follow cross-references
5. Use visual mode in shell for better understanding

## Common Issues
- Large files may take time to analyze
- Some functions might not be detected automatically
- Complex binaries may require manual analysis
- Consider using debug symbols if available 