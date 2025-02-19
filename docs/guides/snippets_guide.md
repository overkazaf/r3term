# Code Snippets Guide

## Basic Commands

### 1. List Snippets
- Command: `list [language]`
- Lists all code snippets
- Optionally filter by language
- Shows ID, title, language, tags, and creation date

### 2. Add Snippet
- Command: `add`
- Creates a new code snippet
- Required information:
  - Title: Brief description
  - Language: Programming language
  - Tags: Comma-separated keywords
- Opens vim editor for content
- Supports syntax highlighting

### 3. Show Snippet
- Command: `show <id>`
- Displays full snippet content
- Shows metadata and code
- Syntax highlighted output
- Usage: `show 1`

### 4. Edit Snippet
- Command: `edit <id>`
- Modifies existing snippet
- Opens vim editor with current content
- Preserves metadata
- Usage: `edit 1`

### 5. Delete Snippet
- Command: `delete <id>`
- Removes snippet permanently
- Requires confirmation
- Usage: `delete 1`

### 6. Search Snippets
- Command: `search <keyword> [language]`
- Searches in titles, content, and tags
- Optional language filter
- Shows where matches were found
- Usage: `search "api" python`

## Tips
- Use meaningful titles and tags
- Add language-specific tags
- Keep snippets focused and concise
- Use comments to explain complex code
- Regular backups recommended

## Best Practices
1. Organize with consistent tags
2. Include usage examples
3. Document dependencies
4. Update outdated snippets
5. Remove unused snippets

## Supported Languages
- Python
- JavaScript
- Java
- C/C++
- Shell Script
- And many more...

## Common Issues
- Always save in vim before quitting
- Use proper language names
- Keep snippets up to date
- Regular cleanup recommended 