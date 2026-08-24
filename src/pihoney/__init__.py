"""pihoney — find out when an autonomous agent read your content and obeyed it.

Prompt-injection defence is usually framed as filtering input. This is the other
side: seeding *bait* so you learn when an agent has scraped your pages and acted on
embedded instructions — a canary-token network for the agent era.

The hard problem is not planting the bait; it is **attribution**. A trigger proves
something fetched the token and followed an instruction. It does not by itself tell
you *who*, and a human clicking a link looks similar. So every finding here carries
an explicit confidence with the reasons behind it, and the tool refuses to claim
more than the evidence supports.
"""
__version__ = "1.0.0"
