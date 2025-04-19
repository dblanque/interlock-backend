from enum import Enum
from typing import List, Optional
import re

def is_encapsulated(v: str) -> bool:
	"""Check if a string is wrapped in parentheses."""
	if not isinstance(v, str):
		raise TypeError("is_encapsulated value must be of type str.")
	return v.startswith("(") and v.endswith(")")

def encapsulate(v: str) -> str:
	"""Properly encapsulate LDAP filter string"""
	if is_encapsulated(v):
		return v
	return f"({v})" if not v.startswith("(") else f"({v})" if not v.endswith(")") else f"({v}"

class LDAPFilterType(Enum):
	"""Enum representing all valid LDAP filter types"""
	AND = "&"
	OR = "|"
	NOT = "!"
	EQUALITY = "equality"
	PRESENCE = "presence"
	SUBSTRING = "substring"
	GREATER_OR_EQUAL = ">="
	LESS_OR_EQUAL = "<="
	APPROXIMATE = "~="

#
# Example usage:
# 	LDAPFilter.and_(
# 		LDAPFilter.eq("givenName", "John"),
# 		LDAPFilter.or_(
# 			LDAPFilter.has("manager"),
# 			LDAPFilter.substr("title", ["ab", "cd"])
# 		)
# 	)

# Output:
# 	(&(givenName=John)(|(manager=*)(title=ab*cd)))
#
class LDAPFilter:
	"""LDAP Filter Constructor class"""
	def __init__(
		self,
		type: LDAPFilterType,
		children: Optional[List["LDAPFilter"]] = None,
		attribute: Optional[str] = None,
		value: Optional[str] = None,
		parts: Optional[List[str]] = None
	):
		self.type = type
		self.children = children if children is not None else []
		self.attribute = attribute
		self.value = value
		self.parts = parts

	def to_string(self) -> str:
		"""Convert filter to LDAP filter string"""
		if self.type in (LDAPFilterType.AND, LDAPFilterType.OR):
			children_str = ''.join(child.to_string() for child in self.children)
			return encapsulate(f"{self.type.value}{children_str}")
		elif self.type == LDAPFilterType.NOT:
			return encapsulate(f"{self.type.value}{self.children[0].to_string()}")
		elif self.type == LDAPFilterType.EQUALITY:
			return encapsulate(f"{self.attribute}={self.value}")
		elif self.type == LDAPFilterType.PRESENCE:
			return encapsulate(f"{self.attribute}=*")
		elif self.type == LDAPFilterType.SUBSTRING:
			value = '*'.join(self.parts or [])
			return encapsulate(f"{self.attribute}={value}")
		elif self.type in (LDAPFilterType.GREATER_OR_EQUAL, 
						  LDAPFilterType.LESS_OR_EQUAL,
						  LDAPFilterType.APPROXIMATE):
			return encapsulate(f"{self.attribute}{self.type.value}{self.value}")
		else:
			raise ValueError(f"Unsupported filter type: {self.type}")

	@classmethod
	def from_string(cls, s: str) -> "LDAPFilter":
		"""Parse an LDAP filter string into an LDAPFilter instance"""
		s = s.strip()
		if not is_encapsulated(s):
			raise ValueError("Filter must be enclosed in parentheses")
		content = s[1:-1].strip()
		if not content:
			raise ValueError("Empty filter content")

		if content[0] in (t.value for t in (LDAPFilterType.AND, LDAPFilterType.OR, LDAPFilterType.NOT)):
			return cls._parse_complex_filter(content)
		return cls._parse_simple_filter(content)

	@classmethod
	def _parse_complex_filter(cls, content: str) -> "LDAPFilter":
		"""Handle AND/OR/NOT filters"""
		first_char = content[0]
		remaining = content[1:].lstrip()

		if first_char == LDAPFilterType.NOT.value:
			if not remaining:
				raise ValueError("NOT filter missing child")
			child_str, remaining = cls._parse_next_filter(remaining)
			if remaining:
				raise ValueError("Unexpected characters after NOT filter")
			return cls.not_(cls.from_string(child_str))

		filter_type = LDAPFilterType.OR
		if first_char == LDAPFilterType.AND.value:
			filter_type = LDAPFilterType.AND

		children = []
		while remaining:
			child_str, remaining = cls._parse_next_filter(remaining)
			children.append(cls.from_string(child_str))
		if not children:
			raise ValueError(f"{filter_type.name} filter requires children")
		return cls(filter_type, children=children)

	@classmethod
	def _parse_next_filter(cls, s: str) -> tuple[str, str]:
		"""Extract next filter component from string"""
		s = s.lstrip()
		if not s.startswith('('):
			raise ValueError("Filter component must start with '('")
		depth, end = 1, None
		for i, c in enumerate(s[1:], 1):
			if c == '(': depth += 1
			elif c == ')': depth -= 1
			if depth == 0:
				end = i + 1
				break
		if end is None:
			raise ValueError("Unmatched parentheses")
		return s[:end], s[end:].lstrip()

	@classmethod
	def _parse_simple_filter(cls, content: str) -> "LDAPFilter":
		"""Handle simple attribute-based filters"""
		match = re.match(r'^([\w$]+)(>=|<=|~=|:=|=)(.*)$', content)
		if not match:
			raise ValueError(f"Invalid filter format: {content}")

		attr, op, value = match.groups()
		if op == '=':
			if value == '*':
				return cls(LDAPFilterType.PRESENCE, attribute=attr)
			return cls._parse_equality_or_substring(attr, value)
		return cls._parse_operator_filter(attr, op, value)

	@classmethod
	def _parse_equality_or_substring(cls, attr: str, value: str) -> "LDAPFilter":
		"""Handle equality or substring filters"""
		if '*' in value:
			return cls(LDAPFilterType.SUBSTRING, 
					  attribute=attr, 
					  parts=value.split('*'))
		return cls(LDAPFilterType.EQUALITY, 
				 attribute=attr, 
				 value=value)

	@classmethod
	def _parse_operator_filter(cls, attr: str, op: str, value: str) -> "LDAPFilter":
		"""Handle comparison operators"""
		try:
			filter_type = {
				'>=': LDAPFilterType.GREATER_OR_EQUAL,
				'<=': LDAPFilterType.LESS_OR_EQUAL,
				'~=': LDAPFilterType.APPROXIMATE
			}[op]
		except KeyError:
			raise ValueError(f"Unsupported operator: {op}")
		return cls(filter_type, attribute=attr, value=value)

	# Factory methods
	@classmethod
	def and_(cls, *filters: "LDAPFilter") -> "LDAPFilter":
		if not filters:
			raise ValueError("AND filter requires children")
		return cls(LDAPFilterType.AND, children=list(filters))

	@classmethod
	def or_(cls, *filters: "LDAPFilter") -> "LDAPFilter":
		if not filters:
			raise ValueError("OR filter requires children")
		return cls(LDAPFilterType.OR, children=list(filters))

	@classmethod
	def not_(cls, filter: "LDAPFilter") -> "LDAPFilter":
		return cls(LDAPFilterType.NOT, children=[filter])

	@classmethod
	def eq(cls, attribute: str, value: str) -> "LDAPFilter":
		return cls(LDAPFilterType.EQUALITY, attribute=attribute, value=value)

	@classmethod
	def has(cls, attribute: str) -> "LDAPFilter":
		return cls(LDAPFilterType.PRESENCE, attribute=attribute)

	@classmethod
	def substr(cls, attribute: str, parts: List[str]) -> "LDAPFilter":
		return cls(LDAPFilterType.SUBSTRING, attribute=attribute, parts=parts)

	def __str__(self) -> str:
		return self.to_string()

	def __repr__(self) -> str:
		return (f"LDAPFilter(type={self.type.name}, attribute={self.attribute}, "
				f"value={self.value}, parts={self.parts}, children={self.children})")
