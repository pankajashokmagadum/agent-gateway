"""Retrieval over the written policies and runbooks in data/policies.

Retrieval informs people and agents. It never decides anything: authorization
is code in gateway/, and the text found here is attached as explanation.
"""

from .retrievers import Lexical, Vector, make_policy_search

__all__ = ["Lexical", "Vector", "make_policy_search"]
