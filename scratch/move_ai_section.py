import os

file_path = r"d:\Study\test\Audio\ai_engineer\DP\week10\vtrust-renew\components\pages\ScamChecker.tsx"

with open(file_path, "r", encoding="utf-8") as f:
    content = f.read()

# 1. Locate the AI Section
start_marker = "                {/* --- New AI Preview Widget and Collapsible Deep Dive (Progressive Disclosure) --- */}"
end_marker = "                )}\n              </>"

start_idx = content.find(start_marker)
if start_idx == -1:
    print("Error: start_marker not found")
    exit(1)

# Find the end_marker after start_idx
end_idx = content.find(end_marker, start_idx)
if end_idx == -1:
    print("Error: end_marker not found")
    exit(1)

# The block to extract ends just before "              </>"
# So we want to extract from start_idx to end_idx + len("                )}")
block_end_idx = end_idx + len("                )}")
ai_block = content[start_idx:block_end_idx]

print(f"Extracted AI block of length: {len(ai_block)}")

# 2. Modify the AI container inside the block to add mb-8
old_container = '<div className="mt-8 space-y-8 w-full animate-[fadeIn_0.5s_ease-out]">'
new_container = '<div className="mt-8 mb-8 space-y-8 w-full animate-[fadeIn_0.5s_ease-out]">'
if old_container in ai_block:
    ai_block = ai_block.replace(old_container, new_container)
    print("Successfully added mb-8 to the AI block container")
else:
    print("Warning: old_container not found inside ai_block, checking with different spacing...")
    # fallback check
    old_container_fallback = '<div className="mt-8 space-y-8 w-full'
    if old_container_fallback in ai_block:
        ai_block = ai_block.replace(old_container_fallback, '<div className="mt-8 mb-8 space-y-8 w-full')
        print("Fallback container replacement succeeded")

# 3. Remove the AI block from the original content
# Also strip the extra newline so we don't leave double blank lines
content_without_ai = content[:start_idx] + content[block_end_idx:]

# 4. Locate the insertion point (right before the Advice Section)
advice_marker = "                {/* Advice Section — hide for VTrust-verified and safe assets */}"
insert_idx = content_without_ai.find(advice_marker)
if insert_idx == -1:
    print("Error: advice_marker not found")
    exit(1)

# Insert the AI block before the Advice Section
final_content = (
    content_without_ai[:insert_idx]
    + ai_block
    + "\n\n"
    + content_without_ai[insert_idx:]
)

# 5. Write back to file
with open(file_path, "w", encoding="utf-8") as f:
    f.write(final_content)

print("Successfully moved the AI block above the Advice Section!")
