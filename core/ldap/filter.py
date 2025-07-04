################################################################################
#################### INTERLOCK IS LICENSED UNDER GNU AGPLv3 ####################
################## ORIGINAL PROJECT CREATED BY DYLAN BLANQUÉ ###################
########################## AND BR CONSULTING S.R.L. ############################
################################################################################
# Module: core.ldap.filter
# Contains the LDAP Filter utilities and classes.

# ---------------------------------- IMPORTS --------------------------------- #
from enum import Enum
from typing import List, Optional
import re
################################################################################


def is_encapsulated(v: str, raise_exception=False) -> bool:
	"""Validate LDAP filter string encapsulation and parenthesis balance.

	Args:
		v: String to validate

	Returns:
		True if properly wrapped in parentheses with balanced delimiters

	Raises:
		TypeError: For non-string inputs
		ValueError: If parentheses are unbalanced
	"""
	if not isinstance(v, str):
		raise TypeError("Input must be a string")

	has_start = v.startswith("(")
	has_end = v.endswith(")")

	if raise_exception:
		if (has_start and not has_end) or (not has_start and has_end):
			raise ValueError(f"Unbalanced parentheses in filter string: {v}")

	return has_start and has_end


def encapsulate(v: str) -> str:
	"""Properly encapsulate LDAP filter string"""
	if is_encapsulated(v):
		return v
	return f"({v})"


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


LDAPFilterRE = re.compile(r"^([\w$]+)(>=|<=|~=|:=|=)(.*)$")


class LDAPFilter:
	"""LDAP Filter Constructor class"""

	def __init__(
		self,
		type: LDAPFilterType,
		children: Optional[List["LDAPFilter"]] = None,
		attribute: Optional[str] = None,
		value: Optional[str] = None,
		parts: Optional[List[str]] = None,
	):
		self.type = type
		self.children = children if children is not None else []
		self.attribute = attribute
		self.value = value
		self.parts = parts

	def to_string(self) -> str:
		"""Convert filter to LDAP filter string"""
		if self.type in (LDAPFilterType.AND, LDAPFilterType.OR):
			children_str = "".join(child.to_string() for child in self.children)
			return encapsulate(f"{self.type.value}{children_str}")
		elif self.type == LDAPFilterType.NOT:
			return encapsulate(
				f"{self.type.value}{self.children[0].to_string()}"
			)
		elif self.type == LDAPFilterType.EQUALITY:
			return encapsulate(f"{self.attribute}={self.value}")
		elif self.type == LDAPFilterType.PRESENCE:
			return encapsulate(f"{self.attribute}=*")
		elif self.type == LDAPFilterType.SUBSTRING:
			value = "*".join(self.parts or [])
			return encapsulate(f"{self.attribute}={value}")
		elif self.type in (
			LDAPFilterType.GREATER_OR_EQUAL,
			LDAPFilterType.LESS_OR_EQUAL,
			LDAPFilterType.APPROXIMATE,
		):
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

		if content[0] in (
			t.value
			for t in (LDAPFilterType.AND, LDAPFilterType.OR, LDAPFilterType.NOT)
		):
			return cls._parse_complex_filter(content)
		return cls._parse_simple_filter(content)

	@classmethod
	def _parse_complex_filter(cls, content: str) -> "LDAPFilter":
		"""Handle AND/OR/NOT filters"""
		first_char = content[0]
		remaining = content[1:].lstrip()

		# NOT filter
		if first_char == LDAPFilterType.NOT.value:
			if not remaining:
				raise ValueError("NOT filter requires a child")
			child_str, remaining = cls._parse_next_filter(remaining)
			if remaining:
				raise ValueError("Unexpected characters after NOT filter")
			return cls.not_(cls.from_string(child_str))

		# AND / OR filters
		filter_type = None
		if first_char == LDAPFilterType.AND.value:
			filter_type = LDAPFilterType.AND
		else:
			filter_type = LDAPFilterType.OR

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
		if not s.startswith("("):
			raise ValueError("Filter component must start with '('")
		depth, end = 1, None
		for i, c in enumerate(s[1:], 1):
			if c == "(":
				depth += 1
			elif c == ")":
				depth -= 1
			if depth == 0:
				end = i + 1
				break
		if end is None:
			raise ValueError("Unmatched parentheses in LDAP Filter string")
		return s[:end], s[end:].lstrip()

	@classmethod
	def _parse_simple_filter(cls, content: str) -> "LDAPFilter":
		"""Handle simple attribute-based filters"""
		match = LDAPFilterRE.match(content)
		if not match:
			raise ValueError(f"Invalid filter format: {content}")

		attr, op, value = match.groups()
		if op == "=":
			if value == "*":
				return cls(LDAPFilterType.PRESENCE, attribute=attr)
			return cls._parse_equality_or_substring(attr, value)
		return cls._parse_operator_filter(attr, op, value)

	@classmethod
	def _parse_equality_or_substring(
		cls, attr: str, value: str
	) -> "LDAPFilter":
		"""Handle equality or substring filters"""
		if "*" in value:
			return cls(
				LDAPFilterType.SUBSTRING, attribute=attr, parts=value.split("*")
			)
		return cls(LDAPFilterType.EQUALITY, attribute=attr, value=value)

	@classmethod
	def _parse_operator_filter(
		cls, attr: str, op: str, value: str
	) -> "LDAPFilter":
		"""Handle comparison operators"""
		try:
			filter_type = {
				">=": LDAPFilterType.GREATER_OR_EQUAL,
				"<=": LDAPFilterType.LESS_OR_EQUAL,
				"~=": LDAPFilterType.APPROXIMATE,
			}[op]
		except KeyError:
			raise ValueError(f"Unsupported operator: {op}")
		return cls(filter_type, attribute=attr, value=value)

	# Factory methods
	@classmethod
	def and_(cls, *filters: "LDAPFilter") -> "LDAPFilter":
		"""LDAPFilter Expression AND, requires children instances (expressions
		or attribute filtering).

		Raises:
			ValueError: Raised if no filter children are passed.

		Returns:
			LDAPFilter: LDAP Filter with AND Expression applied to children.
		"""
		if not filters:
			raise ValueError("AND filter requires children")
		if len(filters) <= 1:
			raise ValueError("AND node should have two or more subnodes.")
		return cls(LDAPFilterType.AND, children=list(filters))

	@classmethod
	def or_(cls, *filters: "LDAPFilter") -> "LDAPFilter":
		"""LDAPFilter Expression OR, requires children LDAPFilter expressions or
		attribute filtering.

		Raises:
			ValueError: Raised if no filter children are passed.

		Returns:
			LDAPFilter: LDAP Filter with OR Expression applied to children.
		"""
		if not filters:
			raise ValueError("OR filter requires children")
		if len(filters) <= 1:
			raise ValueError("OR node should have two or more subnodes.")
		return cls(LDAPFilterType.OR, children=list(filters))

	@classmethod
	def not_(cls, filter: "LDAPFilter") -> "LDAPFilter":
		"""LDAPFilter Expression NOT, requires single LDAPFilter child
		expression or attribute filtering.

		Returns:
			LDAPFilter: LDAP Filter with NOT Expression applied to child.
		"""
		return cls(LDAPFilterType.NOT, children=[filter])

	@classmethod
	def eq(cls, attribute: str, value: str) -> "LDAPFilter":
		"""LDAP Filter Equality Comparison, requires attribute and value.

		Checks for LDAP Attribute exact value match in object attribute field.

		Args:
			attribute (str): LDAP Attribute Field
			value (str): LDAP Attribute Value

		Returns:
			LDAPFilter: Corresponding LDAP Filter.
		"""
		return cls(LDAPFilterType.EQUALITY, attribute=attribute, value=value)

	@classmethod
	def has(cls, attribute: str) -> "LDAPFilter":
		"""LDAP Filter Presence Comparison, requires attribute field.

		Checks for LDAP Attribute existence in object.

		Args:
			attribute (str): LDAP Attribute Field

		Returns:
			LDAPFilter: Corresponding LDAP Filter.
		"""
		return cls(LDAPFilterType.PRESENCE, attribute=attribute)

	@classmethod
	def substr(cls, attribute: str, parts: List[str]) -> "LDAPFilter":
		"""LDAP Filter Substring Comparison, requires attribute and parts.

		Checks for LDAP Attribute substring match in object attribute field.

		Use empty string to manually insert wildcard at start or end of filter,
		otherwise will only add wildcard between parts.

		Args:
			attribute (str): LDAP Attribute Field
			parts (list[str]): LDAP Attribute Value

		Returns:
			LDAPFilter: Corresponding LDAP Filter with substring match.
		"""
		return cls(LDAPFilterType.SUBSTRING, attribute=attribute, parts=parts)

	@classmethod
	def ge(cls, attribute: str, value: str | int) -> "LDAPFilter":
		"""LDAP Filter Greater or Equal Comparison, requires attribute field and
		attribute value.

		Checks for LDAP Attribute existence in object.

		Args:
			attribute (str): LDAP Attribute Field
			value (str or int): LDAP Attribute Value

		Returns:
			LDAPFilter: Corresponding LDAP Filter.
		"""
		return cls(
			LDAPFilterType.GREATER_OR_EQUAL, attribute=attribute, value=value
		)

	@classmethod
	def le(cls, attribute: str, value: str | int) -> "LDAPFilter":
		"""LDAP Filter Less or Equal Comparison, requires attribute field and
		attribute value.

		Checks for LDAP Attribute existence in object.

		Args:
			attribute (str): LDAP Attribute Field
			value (str or int): LDAP Attribute Value

		Returns:
			LDAPFilter: Corresponding LDAP Filter.
		"""
		return cls(
			LDAPFilterType.LESS_OR_EQUAL, attribute=attribute, value=value
		)

	@classmethod
	def approximate(cls, attribute: str, value: str | int) -> "LDAPFilter":
		"""LDAP Filter Approximate Comparison, requires attribute field and
		attribute value.

		Checks for LDAP Attribute existence in object.

		Args:
			attribute (str): LDAP Attribute Field
			value (str or int): LDAP Attribute Value

		Returns:
			LDAPFilter: Corresponding LDAP Filter.
		"""
		return cls(LDAPFilterType.APPROXIMATE, attribute=attribute, value=value)

	def __str__(self) -> str:
		"""Returns stringified LDAP Filter"""
		return self.to_string()

	def __repr__(self) -> str:
		"""String representation of LDAP Filter"""
		return (
			f"LDAPFilter(type={self.type.name}, attribute={self.attribute}, "
			f"value={self.value}, parts={self.parts}, children={self.children})"
		)
