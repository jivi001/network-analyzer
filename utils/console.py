from rich.console import Console

# Single shared Console instance across the entire application lifecycle.
# All TUI views, panels, prompts, and Live renderers MUST use this instance.
console = Console()
