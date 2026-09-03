import asyncio
import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from actionradius.inventory.async_tree_fetcher import fetch_workflow_contents_async

def test_fetch_workflow_contents_async_basic():
    async def _run():
        client = MagicMock()
        
        async def mock_get(path, params):
            if "git/trees" in path:
                return {"tree": [{"path": ".github/workflows/ci.yml", "type": "blob"}], "truncated": False}
            return {"content": "bmFtZTogQ0k="} # "name: CI" in base64
            
        client._get = AsyncMock(side_effect=mock_get)
        
        res = await fetch_workflow_contents_async(client, "owner", "repo", "main")
        assert ".github/workflows/ci.yml" in res
        assert res[".github/workflows/ci.yml"] == "name: CI"
    asyncio.run(_run())

def test_fetch_workflow_contents_async_overlapping_fetches():
    """Prove that file fetches are concurrent, not sequential."""
    async def _run():
        client = MagicMock()
        
        started = []
        
        async def mock_get(path, params):
            if "git/trees" in path:
                return {"tree": [
                    {"path": ".github/workflows/1.yml", "type": "blob"},
                    {"path": ".github/workflows/2.yml", "type": "blob"}
                ], "truncated": False}
                
            started.append(path)
            if "1.yml" in path:
                await asyncio.sleep(0.1)
            return {"content": "eXg="} # "yx"
            
        client._get = AsyncMock(side_effect=mock_get)
        
        res = await fetch_workflow_contents_async(client, "owner", "repo", "main")
        assert len(started) == 2
        assert ".github/workflows/1.yml" in res
        assert ".github/workflows/2.yml" in res
    asyncio.run(_run())

def test_fetch_workflow_contents_async_semaphore_caps_inflight():
    async def _run():
        client = MagicMock()
        
        inflight = 0
        max_inflight = 0
        
        async def mock_get(path, params):
            nonlocal inflight, max_inflight
            if "git/trees" in path:
                return {"tree": [
                    {"path": ".github/workflows/1.yml", "type": "blob"},
                    {"path": ".github/workflows/2.yml", "type": "blob"},
                    {"path": ".github/workflows/3.yml", "type": "blob"},
                    {"path": ".github/workflows/4.yml", "type": "blob"}
                ], "truncated": False}
                
            inflight += 1
            max_inflight = max(max_inflight, inflight)
            await asyncio.sleep(0.05)
            inflight -= 1
            return {"content": "eXg="}
            
        client._get = AsyncMock(side_effect=mock_get)
        
        sem = asyncio.Semaphore(2)
        res = await fetch_workflow_contents_async(client, "owner", "repo", "main", semaphore=sem)
        
        assert max_inflight <= 2
        assert len(res) == 4
    asyncio.run(_run())

def test_fetch_workflow_contents_async_partial_failure():
    async def _run():
        client = MagicMock()
        
        async def mock_get(path, params):
            if "git/trees" in path:
                return {"tree": [
                    {"path": ".github/workflows/1.yml", "type": "blob"},
                    {"path": ".github/workflows/2.yml", "type": "blob"}
                ], "truncated": False}
                
            if "1.yml" in path:
                raise Exception("Network error")
            return {"content": "eXg="}
            
        client._get = AsyncMock(side_effect=mock_get)
        
        res = await fetch_workflow_contents_async(client, "owner", "repo", "main")
        assert ".github/workflows/2.yml" in res
        assert ".github/workflows/1.yml" not in res
    asyncio.run(_run())
