# /ctf.analyze - CTF Challenge Analysis

Analyze the current challenge and suggest approaches.

## When to Use

Use this command when:

- Starting a new CTF challenge
- You have files to analyze but aren't sure what category they are
- You want AI-assisted analysis of challenge files

## How It Works

1. Run `ctf analyze` in the challenge directory to get initial file analysis
2. Read the `.ctf/analysis.md` file if it exists for previous analysis
3. Use the file detection utilities to understand file types
4. Use the strings and file tools to extract information

## Steps to Execute

1. **List files** in the current directory
2. **Run file analysis** using `ctf analyze` command
3. **Extract strings** from binary files using the strings tool
4. **Check for patterns** like flags, URLs, emails, hashes
5. **Suggest category** based on file types and content
6. **Recommend tools** specific to the detected category
7. **Outline approach** with concrete next steps

## Example Workflow

```bash
# Run initial analysis
ctf analyze

# For more detail
ctf analyze -v

# Output as markdown (useful for documentation)
ctf analyze -m > analysis_output.md
```

## Response Format

When responding to /ctf.analyze:

1. **Summary**: Brief overview of what was found
2. **Files**: List each file with type and relevant observations
3. **Category**: Most likely challenge category (crypto, forensics, pwn, etc.)
4. **Key Findings**: Important strings, patterns, or artifacts discovered
5. **Recommended Tools**: Specific tools to use based on findings
6. **Next Steps**: Ordered list of concrete actions to take

## Important Notes

- Always check for flag patterns in strings output
- Look for hidden files or embedded data
- Note any suspicious or interesting patterns
- Consider multiple approaches if category is unclear
- Update `.ctf/analysis.md` with findings

## Related Commands

- `/ctf.crypto` - For cryptography challenges
- `/ctf.forensics` - For forensics challenges
- `/ctf.stego` - For steganography challenges
- `/ctf.web` - For web challenges
- `/ctf.pwn` - For binary exploitation
- `/ctf.reverse` - For reverse engineering
