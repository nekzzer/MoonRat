import hashlib
import json
import time
from datetime import datetime
from typing import Dict, List, Optional

class Block:
    def __init__(self, index: int, timestamp: float, data: dict, previous_hash: str, nonce: int = 0):
        self.index = index
        self.timestamp = timestamp
        self.data = data
        self.previous_hash = previous_hash
        self.nonce = nonce
        self.hash = self.calculate_hash()
    
    def calculate_hash(self) -> str:
        block_string = json.dumps({
            "index": self.index,
            "timestamp": self.timestamp,
            "data": self.data,
            "previous_hash": self.previous_hash,
            "nonce": self.nonce
        }, sort_keys=True)
        return hashlib.sha256(block_string.encode()).hexdigest()
    
    def mine_block(self, difficulty: int):
        target = "0" * difficulty
        while self.hash[:difficulty] != target:
            self.nonce += 1
            self.hash = self.calculate_hash()
    
    def to_dict(self) -> dict:
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "data": self.data,
            "previous_hash": self.previous_hash,
            "nonce": self.nonce,
            "hash": self.hash
        }

class Blockchain:
    def __init__(self, filename: str = "blockchain_users.json", difficulty: int = 2):
        self.filename = filename
        self.difficulty = difficulty
        self.chain: List[Block] = []
        self.load_chain()
    
    def create_genesis_block(self) -> Block:
        genesis_data = {
            "type": "genesis",
            "message": "MoonRise Blockchain Initialized",
            "version": "1.0.0"
        }
        block = Block(0, time.time(), genesis_data, "0")
        block.mine_block(self.difficulty)
        return block
    
    def get_latest_block(self) -> Block:
        return self.chain[-1] if self.chain else None
    
    def add_block(self, data: dict) -> Block:
        latest_block = self.get_latest_block()
        new_block = Block(
            index=latest_block.index + 1,
            timestamp=time.time(),
            data=data,
            previous_hash=latest_block.hash
        )
        new_block.mine_block(self.difficulty)
        self.chain.append(new_block)
        self.save_chain()
        return new_block
    
    def is_chain_valid(self) -> bool:
        for i in range(1, len(self.chain)):
            current = self.chain[i]
            previous = self.chain[i - 1]
            
            if current.hash != current.calculate_hash():
                return False
            
            if current.previous_hash != previous.hash:
                return False
        
        return True
    
    def save_chain(self):
        data = {
            "difficulty": self.difficulty,
            "chain": [block.to_dict() for block in self.chain]
        }
        with open(self.filename, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
    
    def load_chain(self):
        try:
            with open(self.filename, 'r', encoding='utf-8') as f:
                data = json.load(f)
                self.difficulty = data.get("difficulty", 2)
                chain_data = data.get("chain", [])
                
                if not chain_data:
                    self.chain = [self.create_genesis_block()]
                    self.save_chain()
                else:
                    self.chain = []
                    for block_data in chain_data:
                        block = Block(
                            index=block_data["index"],
                            timestamp=block_data["timestamp"],
                            data=block_data["data"],
                            previous_hash=block_data["previous_hash"],
                            nonce=block_data["nonce"]
                        )
                        block.hash = block_data["hash"]
                        self.chain.append(block)
        except FileNotFoundError:
            self.chain = [self.create_genesis_block()]
            self.save_chain()
    
    def add_user(self, username: str, access_key: str, admin: bool = False, ui_settings: dict = None) -> Block:
        # Hash access key for security
        access_key_hash = hashlib.sha256(access_key.encode()).hexdigest()
        
        user_data = {
            "type": "add_user",
            "timestamp": time.time(),
            "username": username,
            "access_key": access_key_hash,
            "access_key_plain": access_key,  # Store plain for compatibility
            "admin": admin,
            "ui_settings": ui_settings or {
                "theme": "#c084fc",
                "background": {"type": "gradient", "url": "", "video_opacity": 30, "video_blur": 0},
                "interface": {"glass_effect": True, "animations": True, "panel_opacity": 100}
            },
            "created_at": datetime.now().isoformat()
        }
        
        return self.add_block(user_data)
    
    def get_user_by_key(self, access_key: str) -> Optional[dict]:
        for block in reversed(self.chain):
            if block.data.get("type") == "add_user":
                if block.data.get("access_key_plain") == access_key:
                    return block.data
        return None
    
    def get_all_users(self) -> Dict[str, dict]:
        users = {}
        for block in self.chain:
            if block.data.get("type") == "add_user":
                key = block.data.get("access_key_plain")
                users[key] = {
                    "username": block.data.get("username"),
                    "admin": block.data.get("admin", False),
                    "ui_settings": block.data.get("ui_settings", {}),
                    "created_at": block.data.get("created_at")
                }
        return users
    
    def update_user_settings(self, access_key: str, ui_settings: dict) -> Block:
        user = self.get_user_by_key(access_key)
        if not user:
            raise ValueError("User not found")
        
        update_data = {
            "type": "update_settings",
            "timestamp": time.time(),
            "access_key": hashlib.sha256(access_key.encode()).hexdigest(),
            "access_key_plain": access_key,
            "ui_settings": ui_settings,
            "updated_at": datetime.now().isoformat()
        }
        
        return self.add_block(update_data)
    
    def delete_user(self, access_key: str) -> Block:
        user = self.get_user_by_key(access_key)
        if not user:
            raise ValueError("User not found")
        
        delete_data = {
            "type": "delete_user",
            "timestamp": time.time(),
            "access_key": hashlib.sha256(access_key.encode()).hexdigest(),
            "access_key_plain": access_key,
            "deleted_at": datetime.now().isoformat()
        }
        
        return self.add_block(delete_data)
    
    def get_user_history(self, access_key: str) -> List[dict]:
        history = []
        access_key_hash = hashlib.sha256(access_key.encode()).hexdigest()
        
        for block in self.chain:
            if block.data.get("access_key") == access_key_hash or \
               block.data.get("access_key_plain") == access_key:
                history.append({
                    "block_index": block.index,
                    "timestamp": block.timestamp,
                    "type": block.data.get("type"),
                    "data": block.data
                })
        
        return history

# Singleton instance
_blockchain_instance = None

def get_blockchain() -> Blockchain:
    global _blockchain_instance
    if _blockchain_instance is None:
        _blockchain_instance = Blockchain()
    return _blockchain_instance
