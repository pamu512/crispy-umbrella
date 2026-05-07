#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Final.py - Social Media Search Coordinator
Responsible for coordinating parameter retrieval and search execution middleware
"""

import json
import logging
import datetime
import time
import traceback
import sys
import os
import argparse
import subprocess
from pathlib import Path

# Fix encoding issues on Windows
if sys.platform.startswith('win'):
    import codecs
    try:
        # Try to set UTF-8 encoding for stdout/stderr
        if hasattr(sys.stdout, 'detach'):
            sys.stdout = codecs.getwriter('utf-8')(sys.stdout.detach())
        if hasattr(sys.stderr, 'detach'):
            sys.stderr = codecs.getwriter('utf-8')(sys.stderr.detach())
    except (AttributeError, OSError):
        # Fallback: just set the environment variable
        pass
    os.environ['PYTHONIOENCODING'] = 'utf-8'

# Import local modules
try:
    from getSearchResult import search_all_platforms
    import importlib.util
    
    # Dynamic import of getCSE.py
    spec = importlib.util.spec_from_file_location("getCSE", "getCSE.py")
    main3 = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(main3)
    
except ImportError as e:
    print(f"Module import failed: {e}")
    exit(1)

class SocialMediaSearchOrchestrator:
    """Social Media Search Coordinator"""
    
    def __init__(self, log_file="search_log.json"):
        # Ensure logs directory exists
        logs_dir = Path("logs")
        logs_dir.mkdir(exist_ok=True)
        
        self.log_file = logs_dir / log_file
        self.session_id = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        self.log_data = {
            "session_id": self.session_id,
            "start_time": datetime.datetime.now().isoformat(),
            "steps": [],
            "parameters": {},
            "results": {},
            "errors": []
        }
        
        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(logs_dir / f'search_{self.session_id}.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
        
    def log_step(self, step_name, status="in_progress", details=None, error=None):
        """Record step"""
        step_entry = {
            "step": step_name,
            "timestamp": datetime.datetime.now().isoformat(),
            "status": status,
            "details": details or {},
            "error": error
        }
        self.log_data["steps"].append(step_entry)
        
        if status == "completed":
            self.logger.info(f"[OK] Step completed: {step_name}")
        elif status == "error":
            self.logger.error(f"[ERROR] Step failed: {step_name} - {error}")
        else:
            self.logger.info(f"[INFO] Starting step: {step_name}")
    
    def get_cse_parameters(self, max_retries=3):
        """Get CSE parameters for all platforms (with retry mechanism)"""
        self.log_step("Get all platform CSE parameters", "in_progress")
        
        for attempt in range(max_retries):
            try:
                if attempt > 0:
                    self.logger.info(f"[RETRY] Retrying parameter retrieval (attempt {attempt + 1})")
                    time.sleep(2 * attempt)  # Exponential backoff
                
                # Call getCSE.py function to get all platform parameters with date sorting
                all_params = main3.get_all_platform_parameters()
                
                # Ensure all platforms have date sorting enabled
                if all_params:
                    for platform, params in all_params.items():
                        if "sort" not in params or not params["sort"]:
                            params["sort"] = "date"
                            self.logger.info(f"Added date sorting for {platform.upper()}")
                
                if all_params and len(all_params) > 0:
                    self.log_data["parameters"] = all_params
                    self.log_step("Get all platform CSE parameters", "completed", {
                        "platforms_count": len(all_params),
                        "platforms": list(all_params.keys()),
                        "attempts": attempt + 1,
                        "date_sorting_enabled": True
                    })
                    return all_params
                else:
                    if attempt == max_retries - 1:
                        error_msg = f"Unable to retrieve CSE parameters for any platform (tried {max_retries} times)"
                        self.log_step("Get all platform CSE parameters", "error", error=error_msg)
                        return None
                    
            except Exception as e:
                error_msg = f"Error occurred while getting CSE parameters (attempt {attempt + 1}): {str(e)}"
                if attempt == max_retries - 1:
                    self.logger.error(error_msg, exc_info=True)
                else:
                    self.logger.warning(error_msg)

                if attempt == max_retries - 1:
                    self.log_step("Get all platform CSE parameters", "error", error=error_msg)
                    self.log_data["errors"].append({
                        "step": "Get all platform CSE parameters",
                        "error": error_msg,
                        "traceback": traceback.format_exc(),
                        "timestamp": datetime.datetime.now().isoformat(),
                        "attempts": max_retries
                    })
                    return None
        
        return None
    
    def save_parameters(self, params, filename="cse_parameters.json"):
        """Save parameters to file"""
        self.log_step("Save parameters", "in_progress")
        
        try:
            # Add timestamp to parameters
            params_with_timestamp = {
                "retrieved_at": datetime.datetime.now().isoformat(),
                "session_id": self.session_id,
                "parameters": params
            }
            
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(params_with_timestamp, f, indent=2, ensure_ascii=False)
            
            self.log_step("Save parameters", "completed", {"filename": filename})
            return True
            
        except Exception as e:
            error_msg = f"Error occurred while saving parameters: {str(e)}"
            self.log_step("Save parameters", "error", error=error_msg)
            return False
    
    def execute_search(self, query, total_num=100, updated_params=None, output_path=None):
        """Execute search"""
        self.log_step("Execute social media search", "in_progress", {
            "query": query,
            "total_num": total_num,
            "using_updated_params": updated_params is not None,
            "output_path": output_path
        })
        
        # Debug output
        if output_path:
            self.logger.info(f"[DEBUG] Output path received: {output_path}")
            self.logger.info(f"[DEBUG] Output path type: {type(output_path)}")
        else:
            self.logger.warning("[DEBUG] No output_path provided, will use default 'output/' directory")
        
        try:
            # Call search function from main.py
            results = search_all_platforms(query, total_num, updated_params, output_path=output_path)
            
            # Summarize results
            results_summary = {}
            for platform, data in results.items():
                results_summary[platform] = len(data) if data else 0
            
            self.log_data["results"] = results_summary
            self.log_step("Execute social media search", "completed", {
                "platforms_searched": list(results.keys()),
                "results_summary": results_summary,
                "total_results": sum(results_summary.values())
            })
            
            return results
            
        except Exception as e:
            error_msg = f"Error occurred while executing search: {str(e)}"
            self.log_step("Execute social media search", "error", error=error_msg)
            self.log_data["errors"].append({
                "step": "Execute social media search",
                "error": error_msg,
                "traceback": traceback.format_exc(),
                "timestamp": datetime.datetime.now().isoformat()
            })
            return None
    
    def save_log(self):
        """Save log"""
        try:
            self.log_data["end_time"] = datetime.datetime.now().isoformat()
            self.log_data["duration"] = str(datetime.datetime.fromisoformat(self.log_data["end_time"]) - 
                                          datetime.datetime.fromisoformat(self.log_data["start_time"]))
            
            with open(self.log_file, 'w', encoding='utf-8') as f:
                json.dump(self.log_data, f, indent=2, ensure_ascii=False)
            
            self.logger.info(f"Log saved to: {self.log_file}")
            
        except Exception as e:
            self.logger.error(f"Failed to save log: {str(e)}")
    
    def stop_all_containers(self):
        """Stop and remove all Docker containers after search completes"""
        self.logger.info("[SHUTDOWN] Stopping and removing all containers...")
        
        # Don't stop ourselves (social_media_search) - it will exit naturally
        # Only stop other containers
        containers_to_stop = ["docker-tor"]
        
        # First, try to use docker-compose down (most reliable way)
        try:
            # Try to find docker-compose.yml
            # In container, the compose file is usually in the mounted volume
            compose_paths = [
                Path("/app/../docker-compose.yml"),  # Parent directory (mounted volume)
                Path("/app/docker-compose.yml"),  # Inside container
                Path.cwd() / "docker-compose.yml",  # Current directory
            ]
            
            compose_file = None
            for path in compose_paths:
                if path.exists():
                    compose_file = path
                    break
            
            if compose_file:
                self.logger.info(f"[SHUTDOWN] Using docker-compose down from {compose_file.parent}")
                # Try Docker Compose V2 first (docker compose), then V1 (docker-compose) for compatibility
                for cmd in [['docker', 'compose', '-f', str(compose_file), 'down'], 
                            ['docker-compose', '-f', str(compose_file), 'down']]:
                    try:
                        result = subprocess.run(
                            cmd,
                            cwd=compose_file.parent,
                            capture_output=True,
                            text=True,
                            timeout=30
                        )
                        
                        if result.returncode == 0:
                            self.logger.info("[SHUTDOWN] docker-compose down completed successfully")
                            if result.stdout:
                                self.logger.info(f"[SHUTDOWN] {result.stdout.strip()}")
                            return  # Success, exit early
                        else:
                            # Try next command
                            continue
                    except FileNotFoundError:
                        # Command not found, try next
                        continue
                    except Exception as e:
                        self.logger.warning(f"[SHUTDOWN] Error with {' '.join(cmd)}: {str(e)}")
                        continue
                
                self.logger.warning("[SHUTDOWN] Both docker-compose commands failed, falling back to individual stop")
        except Exception as e:
            self.logger.warning(f"[SHUTDOWN] docker-compose down error: {str(e)}")
        
        # Fallback: Stop and remove containers individually
        self.logger.info("[SHUTDOWN] Falling back to individual container stop/remove")
        
        for container_name in containers_to_stop:
            try:
                # Check if container exists (running or stopped)
                check_result = subprocess.run(
                    ['docker', 'ps', '-a', '--filter', f'name={container_name}', '--format', '{{.Names}}'],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                
                if container_name in check_result.stdout:
                    # Container exists, stop it first
                    self.logger.info(f"[SHUTDOWN] Stopping container: {container_name}")
                    stop_result = subprocess.run(
                        ['docker', 'stop', container_name],
                        capture_output=True,
                        text=True,
                        timeout=15
                    )
                    
                    if stop_result.returncode == 0:
                        self.logger.info(f"[SHUTDOWN] Container {container_name} stopped")
                        
                        # Remove the container
                        self.logger.info(f"[SHUTDOWN] Removing container: {container_name}")
                        remove_result = subprocess.run(
                            ['docker', 'rm', container_name],
                            capture_output=True,
                            text=True,
                            timeout=10
                        )
                        
                        if remove_result.returncode == 0:
                            self.logger.info(f"[SHUTDOWN] Container {container_name} removed successfully")
                        else:
                            self.logger.warning(f"[SHUTDOWN] Remove failed: {remove_result.stderr.strip()}")
                    else:
                        self.logger.warning(f"[SHUTDOWN] Stop failed: {stop_result.stderr.strip()}")
                else:
                    self.logger.info(f"[SHUTDOWN] Container {container_name} does not exist")
                    
            except subprocess.TimeoutExpired:
                self.logger.warning(f"[SHUTDOWN] Timeout while processing {container_name}")
            except Exception as e:
                self.logger.warning(f"[SHUTDOWN] Error processing {container_name}: {str(e)}")
        
        self.logger.info("[SHUTDOWN] All containers shutdown and removal process completed")
        
        # Small delay to ensure stop operations complete before container exits
        time.sleep(2)
    
    def run_complete_search(self, query, total_num=100, use_updated_params=True, output_path=None):
        """Run complete search process"""
        self.logger.info(f"[START] Starting social media search process - Query: '{query}'")
        if output_path:
            self.logger.info(f"[OUTPUT] Output path: '{output_path}'")
        
        try:
            # Step 1: Get latest CSE parameters
            updated_params = None
            if use_updated_params:
                updated_params = self.get_cse_parameters()
                if updated_params:
                    # Step 2: Save parameters
                    self.save_parameters(updated_params)
            
            # Step 3: Execute search
            results = self.execute_search(query, total_num, updated_params, output_path=output_path)
            
            if results:
                self.logger.info("[SUCCESS] Search process completed!")
                
                # Display summary
                total_results = sum(len(data) if data else 0 for data in results.values())
                self.logger.info(f"[SUMMARY] Search Summary:")
                self.logger.info(f"   Query keyword: {query}")
                self.logger.info(f"   Search platforms: {len(results)} platforms")
                self.logger.info(f"   Total results: {total_results}")
                
                for platform, data in results.items():
                    count = len(data) if data else 0
                    self.logger.info(f"   {platform.upper()}: {count} results")
            
            else:
                self.logger.error("[ERROR] Search failed")
            
        except Exception as e:
            self.logger.error(f"[ERROR] Process execution failed: {str(e)}")
            self.log_data["errors"].append({
                "step": "complete_search",
                "error": str(e),
                "traceback": traceback.format_exc(),
                "timestamp": datetime.datetime.now().isoformat()
            })
        
        finally:
            # Always save log
            self.save_log()
            
            # Stop all containers after search completes
            self.stop_all_containers()


def quick_search(query, total_num=100, use_updated_params=True):
    """
    Quick search function - suitable for script calls
    
    Args:
        query (str): Search keyword
        total_num (int): Number of results per platform
        use_updated_params (bool): Whether to use latest CSE parameters
    
    Returns:
        dict: Search results
    """
    orchestrator = SocialMediaSearchOrchestrator()
    results = orchestrator.run_complete_search(query, total_num, use_updated_params)
    return results


def main():
    """Main function"""
    parser = argparse.ArgumentParser(description='Social Media Search Coordinator')
    parser.add_argument('-v1', '--target', type=str, help='Search target name (keyword)', default=None)
    parser.add_argument('-v2', '--output', type=str, help='Output directory path', default=None)
    parser.add_argument('-n', '--num', type=int, help='Number of results per platform', default=100)
    parser.add_argument('--no-update-params', action='store_true', help='Skip getting latest CSE parameters')
    
    args = parser.parse_args()
    
    # If no arguments provided, use interactive mode
    if args.target is None:
        print("=== Social Media Search Coordinator ===")
        print("This tool will automatically:")
        print("1. Get latest CSE parameters (from getCSE.py)")
        print("2. Save parameters to JSON file")
        print("3. Execute search on all social media platforms (Facebook, Twitter, Instagram, LinkedIn, TikTok, Pinterest)")
        print("4. Save results to CSV files")
        print("5. Record complete execution log")
        print()
        
        # Get user input
        query = input("Please enter search keyword (default: natixis): ").strip() or "natixis"
        
        try:
            total_num = int(input("Please enter number of results per platform (default: 100): ").strip() or "100")
        except ValueError:
            
            total_num = 100
            print("Using default count: 100")
        
        use_updated = input("Get latest CSE parameters? (y/n, default: y): ").strip().lower()
        use_updated_params = use_updated != 'n'
        output_path = None
    else:
        query = args.target
        total_num = args.num
        use_updated_params = not args.no_update_params
        output_path = args.output
    
    print(f"\nStarting search for '{query}' ({total_num} results per platform)...")
    if output_path:
        print(f"Output path: {output_path}")
    print("=" * 50)
    
    # Create coordinator and run
    orchestrator = SocialMediaSearchOrchestrator()
    orchestrator.run_complete_search(query, total_num, use_updated_params, output_path=output_path)


if __name__ == "__main__":
    main()
