"""
CopyKEY Python Tool - Core Module

Local Card Data Management
NO NETWORK COMMUNICATION - Cards stored locally only
"""
import json
import logging
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Optional, Any

logger = logging.getLogger(__name__)


class LocalCardLibrary:
    """
    Local database for storing decoded card data.
    
    This class provides offline storage for card information.
    No cloud sync - completely offline operation.
    """
    
    def __init__(self, library_path: str = None):
        """
        Initialize card library.
        
        Args:
            library_path: Path to library file (default: ~/.copykey/card_library.json)
        """
        if library_path is None:
            library_path = Path.home() / '.copykey' / 'card_library.json'
        self.library_path = Path(library_path)
        self.cards: List[Dict[str, Any]] = []
        self._load_library()
    
    def _load_library(self):
        """Load library from disk"""
        if self.library_path.exists():
            try:
                with open(self.library_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    self.cards = data.get('cards', [])
                logger.info(f"Loaded {len(self.cards)} cards from library")
            except Exception as e:
                logger.error(f"Failed to load library: {e}")
                self.cards = []
        else:
            logger.info("No existing library found, starting fresh")
    
    def _save_library(self):
        """Save library to disk"""
        try:
            self.library_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.library_path, 'w', encoding='utf-8') as f:
                json.dump({
                    'cards': self.cards,
                    'version': 1,
                    'last_updated': datetime.now().isoformat()
                }, f, indent=2, ensure_ascii=False)
            logger.debug(f"Saved library with {len(self.cards)} cards")
        except Exception as e:
            logger.error(f"Failed to save library: {e}")
            raise
    
    def add_card(self, card_data: Dict[str, Any], name: str, 
                 metadata: Dict[str, Any] = None) -> str:
        """
        Add card to library.
        
        Args:
            card_data: Decoded card data (sectors, keys, etc.)
            name: Human-readable name for the card
            metadata: Optional additional metadata
            
        Returns:
            Card ID
        """
        # Generate unique ID
        timestamp = datetime.now().strftime('%Y%m%d%H%M%S%f')
        card_id = f"card_{len(self.cards)}_{timestamp}"
        
        # Normalize UID format
        uid = card_data.get('uid', '')
        if isinstance(uid, bytes):
            uid_hex = uid.hex()
        elif isinstance(uid, str):
            uid_hex = uid.replace(':', '').replace(' ', '').lower()
        else:
            uid_hex = str(uid)
        
        entry = {
            'id': card_id,
            'name': name,
            'uid': uid_hex,
            'card_type': card_data.get('card_type', 'Unknown'),
            'created': datetime.now().isoformat(),
            'modified': datetime.now().isoformat(),
            'metadata': metadata or {},
            'sectors': card_data.get('sectors', []),
            'keys': card_data.get('keys', {}),
            'notes': ''
        }
        
        self.cards.append(entry)
        self._save_library()
        
        logger.info(f"Added card '{name}' (ID: {card_id})")
        return card_id
    
    def get_card(self, card_id: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve card by ID.
        
        Args:
            card_id: Card ID to retrieve
            
        Returns:
            Card data dictionary or None if not found
        """
        for card in self.cards:
            if card['id'] == card_id:
                return card.copy()
        logger.warning(f"Card not found: {card_id}")
        return None
    
    def get_card_by_uid(self, uid: str) -> Optional[Dict[str, Any]]:
        """
        Find card by UID.
        
        Args:
            uid: Card UID to search for
            
        Returns:
            Card data dictionary or None if not found
        """
        uid_normalized = uid.replace(':', '').replace(' ', '').lower()
        
        for card in self.cards:
            if card['uid'].lower() == uid_normalized:
                return card.copy()
        return None
    
    def list_cards(self) -> List[Dict[str, Any]]:
        """
        List all cards (summary only).
        
        Returns:
            List of card summaries (id, name, uid, type, created)
        """
        return [{
            'id': c['id'],
            'name': c['name'],
            'uid': c['uid'],
            'card_type': c['card_type'],
            'created': c['created']
        } for c in self.cards]
    
    def update_card(self, card_id: str, updates: Dict[str, Any]) -> bool:
        """
        Update card metadata.
        
        Args:
            card_id: Card ID to update
            updates: Dictionary of fields to update
            
        Returns:
            True if successful
        """
        for card in self.cards:
            if card['id'] == card_id:
                card.update(updates)
                card['modified'] = datetime.now().isoformat()
                self._save_library()
                logger.info(f"Updated card {card_id}")
                return True
        logger.warning(f"Card not found for update: {card_id}")
        return False
    
    def delete_card(self, card_id: str) -> bool:
        """
        Delete card from library.
        
        Args:
            card_id: Card ID to delete
            
        Returns:
            True if deleted
        """
        for i, card in enumerate(self.cards):
            if card['id'] == card_id:
                del self.cards[i]
                self._save_library()
                logger.info(f"Deleted card {card_id}")
                return True
        logger.warning(f"Card not found for deletion: {card_id}")
        return False
    
    def export_card(self, card_id: str, format: str = 'json') -> Optional[bytes]:
        """
        Export card data for backup or transfer.
        
        Args:
            card_id: Card ID to export
            format: Export format ('json' currently supported)
            
        Returns:
            Exported data as bytes or None if failed
        """
        card = self.get_card(card_id)
        if not card:
            return None
        
        if format == 'json':
            return json.dumps(card, indent=2, ensure_ascii=False).encode('utf-8')
        else:
            logger.error(f"Unsupported export format: {format}")
            return None
    
    def import_card(self, data: bytes, format: str = 'json') -> Optional[str]:
        """
        Import card data from external source.
        
        Args:
            data: Imported data
            format: Import format ('json' currently supported)
            
        Returns:
            New card ID or None if failed
        """
        try:
            if format == 'json':
                card_data = json.loads(data.decode('utf-8'))
                
                # Validate required fields
                if 'uid' not in card_data:
                    logger.error("Imported card missing UID")
                    return None
                
                # Create new entry
                card_id = self.add_card(
                    card_data=card_data,
                    name=card_data.get('name', 'Imported Card'),
                    metadata={'imported': True, 'import_date': datetime.now().isoformat()}
                )
                
                logger.info(f"Imported card as {card_id}")
                return card_id
            else:
                logger.error(f"Unsupported import format: {format}")
                return None
        except Exception as e:
            logger.error(f"Import failed: {e}")
            return None
    
    def search_cards(self, query: str) -> List[Dict[str, Any]]:
        """
        Search cards by name, UID, or notes.
        
        Args:
            query: Search query string
            
        Returns:
            List of matching card summaries
        """
        query_lower = query.lower()
        results = []
        
        for card in self.cards:
            if (query_lower in card['name'].lower() or
                query_lower in card['uid'].lower() or
                query_lower in card.get('notes', '').lower()):
                results.append({
                    'id': card['id'],
                    'name': card['name'],
                    'uid': card['uid'],
                    'card_type': card['card_type'],
                    'created': card['created']
                })
        
        logger.info(f"Search '{query}' found {len(results)} cards")
        return results
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get library statistics.
        
        Returns:
            Dictionary with library stats
        """
        card_types = {}
        for card in self.cards:
            card_type = card['card_type']
            card_types[card_type] = card_types.get(card_type, 0) + 1
        
        return {
            'total_cards': len(self.cards),
            'card_types': card_types,
            'library_path': str(self.library_path),
            'last_updated': max((c['modified'] for c in self.cards), default=None)
        }
    
    def clear_library(self, confirm: bool = False):
        """
        Clear all cards from library.
        
        Args:
            confirm: Must be True to prevent accidental deletion
        """
        if not confirm:
            raise ValueError("Must set confirm=True to clear library")
        
        self.cards = []
        self._save_library()
        logger.warning("Library cleared")
    
    def __len__(self) -> int:
        """Return number of cards in library"""
        return len(self.cards)
    
    def __iter__(self):
        """Iterate over card summaries"""
        return iter(self.list_cards())
    
    def __repr__(self) -> str:
        return f"LocalCardLibrary({len(self.cards)} cards)"
