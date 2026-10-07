"""
Access control and configuration matching module for HBlink4
"""

import re
from typing import Optional, Dict, Any, List, Tuple, Union, Literal
from dataclasses import dataclass, field

MatchType = Literal['specific_id', 'id_range', 'callsign']
PatternValue = Union[List[int], List[Tuple[int, int]], List[str]]

class InvalidPatternError(Exception):
    """Raised when a pattern configuration is invalid"""

def validate_pattern(match_type: Literal['specific_id', 'id_range', 'callsign'], pattern: Any) -> None:
    """Validate a pattern value against its declared type"""
    if not isinstance(pattern, list):
        raise InvalidPatternError(f"{match_type} pattern must be a list")

    if match_type == 'specific_id':
        if not all(isinstance(x, int) for x in pattern):
            raise InvalidPatternError("Specific ID patterns must contain only integers")
            
    elif match_type == 'id_range':
        for start, end in pattern:
            if not isinstance(start, int) or not isinstance(end, int):
                raise InvalidPatternError("Range bounds must be integers")
            if start > end:
                raise InvalidPatternError(f"Invalid range: start ({start}) > end ({end})")
            
    else:  # callsign
        if not all(isinstance(p, str) and re.match(r'^[A-Za-z0-9*]+$', p) for p in pattern):
            raise InvalidPatternError("Callsign patterns must contain only alphanumeric characters and *")

class BlacklistError(Exception):
    """Raised when a repeater matches a blacklist pattern"""
    def __init__(self, pattern_name: str, reason: str):
        self.pattern_name = pattern_name
        self.reason = reason
        super().__init__(f"Repeater blocked by {pattern_name}: {reason}")

@dataclass
class BlacklistMatch:
    """Represents a blacklist pattern"""
    name: str
    description: str
    ids: List[int] = field(default_factory=list)
    id_ranges: List[Tuple[int, int]] = field(default_factory=list)
    callsigns: List[str] = field(default_factory=list)
    reason: str = ''

    def __post_init__(self):
        """Validate all patterns"""
        if self.ids:
            validate_pattern('specific_id', self.ids)
        if self.id_ranges:
            validate_pattern('id_range', self.id_ranges)
        if self.callsigns:
            validate_pattern('callsign', self.callsigns)

@dataclass
class RepeaterConfig:
    """Configuration settings for a matched repeater"""
    passphrase: str
    # None = allow all TGs, [] = deny all TGs, [1,2,3] = specific TGs
    slot1_talkgroups: Optional[List[int]] = None
    slot2_talkgroups: Optional[List[int]] = None
    trust: bool = False  # If True, use requested TGs as-is (config = defaults only)
    # Per-pattern default for unit (private) call participation. Repeaters can
    # override via UNIT=true|false in RPTO. Absent UNIT in RPTO = use this.
    default_unit_calls: bool = False
    # Server-side slot/talkgroup remaps, set by whoever writes the config (so they
    # apply to untrusted repeaters too): {"<net slot>": ["<net tgid>:<local slot>[:<local
    # tgid>]", ...]}, the RPTO translation grammar. E.g. {"2": ["3027:1"]} delivers
    # network TS2/3027 on the repeater's TS1, and takes its TS1/3027 as network TS2/3027.
    # A trusted repeater's own RPTO translations replace these.
    translations: Optional[Dict[str, List[str]]] = None
    # PTT activation. Talkgroups not on the slot lists above that the repeater may
    # still bring up by keying them: each slot then carries the one it keyed last until
    # `ptt_timeout` seconds pass with no local traffic on it. None = no PTT activation.
    # Runtime state only -- activations live on the connection, never in this config.
    ptt_talkgroups: Optional[List[int]] = None
    ptt_timeout: int = 900
    # The network slot an activation lives on. None = the slot it was keyed on. A
    # hotspot server that puts every talkgroup on one network slot sets it, so a
    # talkgroup keyed on the other slot is heard back on that one.
    ptt_slot: Optional[int] = None

    def __post_init__(self):
        if self.ptt_talkgroups is not None and (
                not isinstance(self.ptt_talkgroups, list)
                or not all(isinstance(t, int) and 0 < t < 0x1000000 for t in self.ptt_talkgroups)):
            raise ValueError('ptt_talkgroups must be a list of talkgroup numbers')
        if isinstance(self.ptt_timeout, bool) or not isinstance(self.ptt_timeout, int) \
                or self.ptt_timeout <= 0:
            raise ValueError('ptt_timeout must be a positive number of seconds')
        if self.ptt_slot not in (None, 1, 2):
            raise ValueError('ptt_slot must be 1 or 2')
        if self.translations is None:
            return
        if not isinstance(self.translations, dict):
            raise ValueError('translations must be an object keyed by network slot')
        for slot, entries in self.translations.items():
            if str(slot) not in ('1', '2'):
                raise ValueError(f'translations: network slot must be 1 or 2, got {slot!r}')
            if not isinstance(entries, list):
                raise ValueError(f'translations[{slot!r}] must be a list')
            for e in entries:
                if not isinstance(e, str) or not _TRANSLATION.match(e):
                    raise ValueError(f'translations[{slot!r}]: {e!r} is not '
                                     f'"<net tgid>[-<net tgid>]:<local slot>[:<local tgid>]"')


_TRANSLATION = re.compile(r'^\s*\d+(-\d+)?\s*:\s*[12*]?\s*(:\s*(\d+|\*)\s*)?$')

@dataclass
class PatternMatch:
    """Represents a pattern matching rule for repeater configuration"""
    name: str
    config: RepeaterConfig
    description: str = ''  # Optional description of the pattern
    # Support multiple match types in one pattern (evaluated with OR logic)
    ids: List[int] = field(default_factory=list)
    id_ranges: List[Tuple[int, int]] = field(default_factory=list)
    callsigns: List[str] = field(default_factory=list)

    def __post_init__(self):
        """Validate all patterns"""
        if self.ids:
            validate_pattern('specific_id', self.ids)
        if self.id_ranges:
            validate_pattern('id_range', self.id_ranges)
        if self.callsigns:
            validate_pattern('callsign', self.callsigns)
        
        # At least one match type must be specified
        if not (self.ids or self.id_ranges or self.callsigns):
            raise InvalidPatternError(f"Pattern '{self.name}' must specify at least one match type")

class RepeaterMatcher:
    """
    Handles repeater identification and configuration matching
    """
    def __init__(self, config: Dict[str, Any]):
        self.blacklist = self._parse_blacklist(config.get('blacklist', {"patterns": []}))
        repeater_config = config.get('repeater_configurations', config.get('repeaters', {}))
        self.patterns = self._parse_patterns(repeater_config.get('patterns', []))
        
        # Make default config optional - only use if explicitly provided
        if 'default' in repeater_config:
            self.default_config = RepeaterConfig(**repeater_config['default'])
        else:
            self.default_config = None

    def _parse_blacklist(self, blacklist_config: Dict[str, Any]) -> List[BlacklistMatch]:
        """Parse blacklist patterns from config - supports multiple match types per pattern"""
        result = []
        for pattern in blacklist_config['patterns']:
            match_dict = pattern['match']
            
            # Extract all match types (can be multiple)
            ids = match_dict.get('ids', [])
            id_ranges = [tuple(r) for r in match_dict.get('id_ranges', [])]
            callsigns = match_dict.get('callsigns', [])
            
            result.append(BlacklistMatch(
                name=pattern['name'],
                description=pattern['description'],
                ids=ids,
                id_ranges=id_ranges,
                callsigns=callsigns,
                reason=pattern['reason']
            ))
        return result

    def _parse_patterns(self, patterns: List[Dict[str, Any]]) -> List[PatternMatch]:
        """Parse pattern configurations from config file - supports multiple match types per pattern"""
        result = []
        for pattern in patterns:
            match_dict = pattern['match']
            config = RepeaterConfig(**pattern['config'])
            
            # Extract all match types (can be multiple)
            ids = match_dict.get('ids', [])
            id_ranges = [tuple(r) for r in match_dict.get('id_ranges', [])]
            callsigns = match_dict.get('callsigns', [])
            
            result.append(PatternMatch(
                name=pattern['name'],
                description=pattern.get('description', ''),
                config=config,
                ids=ids,
                id_ranges=id_ranges,
                callsigns=callsigns
            ))
        
        # No need to sort - patterns are evaluated in order, first match wins
        return result

    def _match_pattern(self, radio_id: int, callsign: Optional[str], pattern: Union[BlacklistMatch, PatternMatch]) -> bool:
        """Match a repeater against a pattern - checks all match types with OR logic"""
        # Check specific IDs
        if pattern.ids and radio_id in pattern.ids:
            return True
        
        # Check ID ranges
        if pattern.id_ranges and any(start <= radio_id <= end for start, end in pattern.id_ranges):
            return True
        
        # Check callsign patterns
        if pattern.callsigns and callsign:
            for p in pattern.callsigns:
                pattern_regex = p.replace('*', '.*') if '*' in p else re.escape(p)
                if re.match(f"^{pattern_regex}$", callsign, re.IGNORECASE):
                    return True
        
        return False

    def _check_blacklist(self, radio_id: int, callsign: Optional[str] = None) -> None:
        """Check if a repeater matches any blacklist patterns"""
        for pattern in self.blacklist:
            if self._match_pattern(radio_id, callsign, pattern):
                raise BlacklistError(pattern.name, pattern.reason)

    def get_repeater_config(self, radio_id: int, callsign: Optional[str] = None) -> Optional[RepeaterConfig]:
        """
        Get the configuration for a connecting repeater based on its ID and/or callsign.
        First checks blacklist, then checks patterns in order (first match wins).
        Within each pattern, match priority is: specific IDs -> ID ranges -> callsign patterns
        
        Patterns can now contain multiple match types (ids, id_ranges, callsigns) for flexibility.
        
        Returns None if no patterns match and no default configuration is defined.
        
        Raises:
            BlacklistError: If the repeater matches any blacklist pattern
        """
        # Check blacklist first
        self._check_blacklist(radio_id, callsign)
        
        # Patterns are already sorted by specificity in _parse_patterns
        for pattern in self.patterns:
            if self._match_pattern(radio_id, callsign, pattern):
                return pattern.config

        # If no patterns match, return default configuration (or None if not defined)
        return self.default_config

    def get_pattern_for_repeater(self, radio_id: int, callsign: Optional[str] = None) -> Optional[PatternMatch]:
        """
        Return the pattern that matched this repeater, or None if using default config.
        Used for dashboard display of which pattern was matched.
        
        Raises:
            BlacklistError: If the repeater matches any blacklist pattern
        """
        # Check blacklist first
        self._check_blacklist(radio_id, callsign)
        
        # Find the matching pattern
        for pattern in self.patterns:
            if self._match_pattern(radio_id, callsign, pattern):
                return pattern
        
        # No pattern matched, using default
        return None
