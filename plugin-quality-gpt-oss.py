import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import asyncio
import json
import logging
from dataclasses import dataclass
from typing import Dict, List, Tuple
import hashlib

try:
    import ollama
    OLLAMA_AVAILABLE = True
except ImportError:
    OLLAMA_AVAILABLE = False

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

@dataclass
class SecurityAssessment:
    plugin_slug: str
    risk_level: str
    confidence_score: float
    vulnerabilities: List[str]
    recommendations: List[str]
    agent_consensus: Dict[str, str]
    risk_score: float

class BaseAgent:
    def __init__(self, model_name="gpt-oss:20b"):
        self.model_name = model_name
        self.agent_name = self.__class__.__name__
        self.use_ollama = OLLAMA_AVAILABLE
        if self.use_ollama:
            self._check_model_availability()
    
    def _check_model_availability(self):
        try:
            models_response = ollama.list()
            if hasattr(models_response, 'models'):
                model_list = models_response.models
            else:
                model_list = models_response
            
            available_models = [m.model for m in model_list if hasattr(m, 'model')]
            model_found = any(self.model_name in model_name_str for model_name_str in available_models)
            
            if not model_found:
                logger.warning(f"Model '{self.model_name}' not found. Available: {available_models}")
                self.use_ollama = False
        except Exception as e:
            logger.error(f"Failed to connect to Ollama: {e}")
            self.use_ollama = False
    
    async def _call_ollama(self, prompt: str) -> str:
        if not self.use_ollama:
            return self._fallback_response()
        
        try:
            response = ollama.chat(
                model=self.model_name,
                messages=[{"role": "user", "content": prompt}],
                options={
                    "temperature": 0.1,
                    "top_k": 10,
                    "top_p": 0.9
                }
            )
            return response['message']['content']
        except Exception as e:
            logger.error(f"Ollama API error: {e}")
            return self._fallback_response()
    
    def _fallback_response(self) -> str:
        return '{"risk_level": "MEDIUM", "confidence": 0.5, "concerns": ["Analysis unavailable"], "reasoning": "Fallback response"}'
    
    def _parse_response(self, response: str) -> Dict:
        try:
            json_start = response.find('{')
            json_end = response.rfind('}') + 1
            if json_start != -1 and json_end != 0:
                json_text = response[json_start:json_end]
                return json.loads(json_text)
        except:
            pass
        return {"risk_level": "UNKNOWN", "confidence": 0.0, "concerns": [], "reasoning": "Parse error"}
    
    async def assess(self, plugin_data: Dict) -> Dict:
        raise NotImplementedError

class CommunityTrustAgent(BaseAgent):
    async def assess(self, plugin_data: Dict) -> Dict:
        support_ratio = plugin_data.get('support_threads_resolved', 0) / max(plugin_data.get('support_threads', 1), 1)
        rating = plugin_data.get('rating', 0)
        num_ratings = plugin_data.get('num_ratings', 0)
        active_installs = plugin_data.get('active_installs', 0)
        
        prompt = f"""Analyze WordPress plugin community trust and provide specific security concerns. Respond with ONLY JSON:

Plugin: {plugin_data['slug']}
Rating: {rating}/100
Ratings Count: {num_ratings}
Support Threads: {plugin_data['support_threads']}
Resolved Threads: {plugin_data['support_threads_resolved']}
Resolution Ratio: {support_ratio:.2f}
Active Installs: {active_installs}

Analyze these specific risks:
- Low or no user ratings (indicates lack of community validation)
- Poor support response (unresolved issues may indicate security holes)
- Low active installations (less community oversight)
- Poor rating scores (user dissatisfaction may indicate problems)

Response format:
{{
    "risk_level": "LOW|MEDIUM|HIGH|CRITICAL",
    "confidence": 0.0-1.0,
    "concerns": ["Detailed concern with specific implications", "Another specific security concern"],
    "reasoning": "brief explanation of community trust assessment"
}}"""
        
        response = await self._call_ollama(prompt)
        return self._parse_response(response)

class VulnerabilityIntelAgent(BaseAgent):
    async def assess(self, plugin_data: Dict) -> Dict:
        slug = plugin_data['slug']
        version = plugin_data['version']
        
        vulnerabilities = await self._check_vulnerability_patterns(slug, version)
        
        prompt = f"""Analyze WordPress plugin vulnerability intelligence. Respond with ONLY JSON:

Plugin: {slug}
Version: {version}
Potential Vulnerabilities: {len(vulnerabilities)}
Risk Patterns: {json.dumps(vulnerabilities[:3])}

Response format:
{{
    "risk_level": "LOW|MEDIUM|HIGH|CRITICAL",
    "confidence": 0.0-1.0,
    "concerns": ["security concern1", "concern2"],
    "reasoning": "brief explanation"
}}"""
        
        response = await self._call_ollama(prompt)
        return self._parse_response(response)
    
    async def _check_vulnerability_patterns(self, slug: str, version: str) -> List[Dict]:
        vulnerabilities = []
        high_risk_patterns = ['admin', 'login', 'upload', 'file-manager', 'backup', 'security', 'database']
        
        if any(pattern in slug.lower() for pattern in high_risk_patterns):
            vulnerabilities.append({
                "type": "high_privilege_functionality",
                "severity": "HIGH",
                "description": "Plugin handles sensitive operations"
            })
        
        return vulnerabilities

class CodeQualityAgent(BaseAgent):
    async def assess(self, plugin_data: Dict) -> Dict:
        homepage = plugin_data.get('homepage', '')
        php_version = plugin_data.get('requires_php', 'Unknown')
        
        repo_analysis = self._analyze_repository_indicators(homepage)
        
        prompt = f"""Analyze WordPress plugin code quality indicators. Respond with ONLY JSON:

Plugin: {plugin_data['slug']}
Homepage: {homepage}
PHP Required: {php_version}
Repository Available: {repo_analysis['has_repo']}
WordPress Compatibility: {plugin_data['requires']} - {plugin_data['tested']}

Response format:
{{
    "risk_level": "LOW|MEDIUM|HIGH|CRITICAL",
    "confidence": 0.0-1.0,
    "concerns": ["quality concern1", "concern2"],
    "reasoning": "brief explanation"
}}"""
        
        response = await self._call_ollama(prompt)
        return self._parse_response(response)
    
    def _analyze_repository_indicators(self, homepage: str) -> Dict:
        if 'github.com' in homepage or 'gitlab.com' in homepage:
            return {"has_repo": True, "platform": "git"}
        else:
            return {"has_repo": False, "platform": "unknown"}

class UpdateFrequencyAgent(BaseAgent):
    """Analyze plugin update patterns and WordPress compatibility"""
    async def assess(self, plugin_data: Dict) -> Dict:
        last_updated_str = str(plugin_data.get('last_updated', ''))
        
        try:
            if 'GMT' in last_updated_str:
                last_updated_str = last_updated_str.replace('GMT', '').strip()
            
            last_updated = pd.to_datetime(last_updated_str, errors='coerce')
            if pd.isna(last_updated):
                days_since_update = 9999
            else:

                if last_updated.tz is not None:
                    last_updated = last_updated.tz_localize(None)
                days_since_update = (datetime.now() - last_updated).days
        except Exception:
            days_since_update = 9999
        

        wp_tested = str(plugin_data.get('tested', ''))
        wp_required = str(plugin_data.get('requires', ''))
        current_wp_major = 6.6 
        
        prompt = f"""Analyze WordPress plugin update patterns and compatibility. Provide detailed security concerns. Respond with ONLY JSON:

Plugin: {plugin_data['slug']}
Days Since Update: {days_since_update}
WordPress Tested: {wp_tested}
WordPress Required: {wp_required}
Current WordPress: 6.6+

Analyze these specific risks:
- Outdated plugin version (>365 days = HIGH risk, >730 days = CRITICAL)
- WordPress compatibility issues 
- Maintenance and support concerns

Response format:
{{
    "risk_level": "LOW|MEDIUM|HIGH|CRITICAL",
    "confidence": 0.0-1.0,
    "concerns": ["Detailed concern with explanation", "Another specific concern"],
    "reasoning": "brief explanation of risk assessment"
}}"""
        
        response = await self._call_ollama(prompt)
        return self._parse_response(response)

class ConsensusAgent(BaseAgent):
    def __init__(self):
        super().__init__()
        self.risk_weights = {
            'CommunityTrustAgent': 0.30,
            'VulnerabilityIntelAgent': 0.35,
            'CodeQualityAgent': 0.20,
            'UpdateFrequencyAgent': 0.15
        }
    
    async def assess(self, plugin_data: Dict, agent_results: Dict[str, Dict]) -> SecurityAssessment:
        risk_scores = {'LOW': 1, 'MEDIUM': 2, 'HIGH': 4, 'CRITICAL': 5, 'UNKNOWN': 2}
        
        weighted_score = 0
        total_weight = 0
        all_concerns = []
        agent_consensus = {}
        
        for agent_name, result in agent_results.items():
            weight = self.risk_weights.get(agent_name, 0.1)
            risk_score = risk_scores.get(result.get('risk_level', 'UNKNOWN'), 2)
            confidence = result.get('confidence', 0.5)
            

            effective_weight = weight * confidence
            weighted_score += risk_score * effective_weight
            total_weight += effective_weight
            
            all_concerns.extend(result.get('concerns', []))
            agent_consensus[agent_name] = result.get('risk_level', 'UNKNOWN')
        
        if total_weight > 0:
            final_score = weighted_score / total_weight
        else:
            final_score = 2.0
        
        final_score_rounded = round(final_score)

        if final_score_rounded >= 5:
            final_risk = 'CRITICAL'
        elif final_score_rounded >= 4:
            final_risk = 'HIGH'
        elif final_score_rounded >= 2:
            final_risk = 'MEDIUM'
        else:
            final_risk = 'LOW'
        
        recommendations = self._generate_recommendations(final_risk, all_concerns)
        
        return SecurityAssessment(
            plugin_slug=plugin_data['slug'],
            risk_level=final_risk,
            confidence_score=total_weight,
            vulnerabilities=list(set(all_concerns)),
            recommendations=recommendations,
            agent_consensus=agent_consensus,
            risk_score=final_score_rounded  
        )
    
    def _generate_recommendations(self, risk_level: str, concerns: List[str]) -> List[str]:
        base_recommendations = {
            'CRITICAL': [
                "🚨 DO NOT INSTALL - Critical security risks identified",
                "🔍 Find alternative plugin with better security record",
                "🗑️ If already installed, remove immediately"
            ],
            'HIGH': [
                "⚠️ Avoid installation unless absolutely necessary",
                "🛡️ Implement additional security monitoring if used",
                "🔄 Consider safer alternatives"
            ],
            'MEDIUM': [
                "⚡ Proceed with caution",
                "📅 Monitor for updates regularly",
                "💾 Implement backup strategy before installation"
            ],
            'LOW': [
                "✅ Generally safe to install",
                "🔄 Keep monitoring for updates",
                "🛡️ Follow standard security practices"
            ]
        }
        return base_recommendations.get(risk_level, ["❓ No specific recommendations"])

class MultiAgentSecurityPipeline:
    def __init__(self):
        self.agents = {
            'CommunityTrustAgent': CommunityTrustAgent(),
            'VulnerabilityIntelAgent': VulnerabilityIntelAgent(),
            'CodeQualityAgent': CodeQualityAgent(),
            'UpdateFrequencyAgent': UpdateFrequencyAgent()
        }
        self.consensus_agent = ConsensusAgent()
    
    async def assess_plugin(self, plugin_data: Dict) -> SecurityAssessment:
        print(f"\n🔍 Analyzing Plugin: {plugin_data['slug']}")
        
        agent_tasks = []
        for agent_name, agent in self.agents.items():
            task = agent.assess(plugin_data)
            agent_tasks.append((agent_name, task))
        
        agent_results = {}
        for agent_name, task in agent_tasks:
            try:
                result = await task
                risk_emoji = {'LOW': '🟢', 'MEDIUM': '🟡', 'HIGH': '🟠', 'CRITICAL': '🔴', 'UNKNOWN': '⚪'}
                emoji = risk_emoji.get(result.get('risk_level', 'UNKNOWN'), '⚪')
                print(f"  {emoji} {agent_name}: {result.get('risk_level', 'UNKNOWN')}")
                agent_results[agent_name] = result
            except Exception as e:
                print(f"  ❌ {agent_name}: ERROR - {str(e)}")
                agent_results[agent_name] = {
                    'risk_level': 'UNKNOWN',
                    'confidence': 0.0,
                    'concerns': [f"Agent error: {str(e)}"],
                    'reasoning': 'Agent failed to complete assessment'
                }
        
        assessment = await self.consensus_agent.assess(plugin_data, agent_results)

        risk_emoji = {'LOW': '🟢', 'MEDIUM': '🟡', 'HIGH': '🟠', 'CRITICAL': '🔴'}
        emoji = risk_emoji.get(assessment.risk_level, '⚪')
        
        print(f"\n{emoji} FINAL ASSESSMENT: {assessment.risk_level}")
        print(f"📊 Risk Score: {assessment.risk_score:.2f}/4.0")
        print(f"🎯 Confidence: {assessment.confidence_score:.2f}")
        
        if assessment.vulnerabilities:
            print(f"⚠️ Key Concerns:")
            for concern in assessment.vulnerabilities[:3]:
                print(f"  • {concern}")
        
        print(f"💡 Top Recommendation: {assessment.recommendations[0]}")
        print("─" * 80)
        
        return assessment
    
    async def assess_dataset(self, df: pd.DataFrame, max_plugins: int = None) -> List[SecurityAssessment]:
        plugins_to_assess = df.head(max_plugins) if max_plugins else df
        print(f"🚀 Starting assessment of {len(plugins_to_assess)} plugins...")
        print("=" * 80)
        
        assessments = []
        for idx, row in plugins_to_assess.iterrows():
            plugin_data = row.to_dict()
            assessment = await self.assess_plugin(plugin_data)
            assessments.append(assessment)
            await asyncio.sleep(0.1)  
        
        return assessments
    
    def save_results(self, assessments: List[SecurityAssessment], output_file: str):
        results = []
        for assessment in assessments:
            results.append({
                'plugin_slug': assessment.plugin_slug,
                'risk_level': assessment.risk_level,
                'risk_score': assessment.risk_score,
                'confidence_score': assessment.confidence_score,
                'vulnerabilities': '; '.join(assessment.vulnerabilities),
                'recommendations': '; '.join(assessment.recommendations),
                'agent_consensus': json.dumps(assessment.agent_consensus)
            })
        
        results_df = pd.DataFrame(results)
        results_df.to_csv(output_file, index=False)
        print(f"💾 Results saved to {output_file}")

async def main():
    print("🔐 WordPress Plugin Security Assessment Pipeline")
    print("=" * 50)
    
    logger.info("Loading WordPress plugins dataset...")
    
    try:
        df = pd.read_excel('wordpress_active_plugins_dataset.xlsx')
        logger.info(f"Loaded {len(df)} plugins from dataset")
    except Exception as e:
        logger.error(f"Failed to load dataset: {e}")
        return
    
    df['last_updated'] = pd.to_datetime(df['last_updated'], errors='coerce', utc=True).dt.tz_localize(None)
    
    print(f"\n📊 Dataset contains {len(df)} plugins")
    sample_sizes = [5, 10, 25, 50]
    
    print("Choose sample size for testing:")
    for i, size in enumerate(sample_sizes, 1):
        print(f"  {i}. {size} plugins")
    
    try:
        choice = int(input("\nEnter your choice (1-4): "))
        max_plugins = sample_sizes[choice - 1]
    except (ValueError, IndexError):
        max_plugins = 10
        print(f"Using default: {max_plugins} plugins")
    
    pipeline = MultiAgentSecurityPipeline()
    assessments = await pipeline.assess_dataset(df, max_plugins=max_plugins)
    
    pipeline.save_results(assessments, f'security_assessment_{max_plugins}_plugins.csv')
    
    print("\n" + "=" * 80)
    print("📈 ASSESSMENT SUMMARY")
    print("=" * 80)
    
    risk_counts = {}
    for assessment in assessments:
        risk_counts[assessment.risk_level] = risk_counts.get(assessment.risk_level, 0) + 1
    
    risk_emoji = {'LOW': '🟢', 'MEDIUM': '🟡', 'HIGH': '🟠', 'CRITICAL': '🔴'}
    for risk_level in ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']:
        count = risk_counts.get(risk_level, 0)
        emoji = risk_emoji.get(risk_level, '⚪')
        if count > 0:
            print(f"{emoji} {risk_level}: {count} plugins")
    
    critical_plugins = [a for a in assessments if a.risk_level in ['CRITICAL', 'HIGH']]
    if critical_plugins:
        print(f"\n🚨 HIGH-RISK PLUGINS ({len(critical_plugins)})")
        print("─" * 50)
        for assessment in critical_plugins[:5]:
            emoji = risk_emoji.get(assessment.risk_level, '⚪')
            print(f"\n{emoji} {assessment.plugin_slug}")
            print(f"   Risk Score: {assessment.risk_score:.2f}/4.0")
            print(f"   Confidence: {assessment.confidence_score:.2f}")
            print(f"   Action: {assessment.recommendations[0]}")

if __name__ == "__main__":
    if not OLLAMA_AVAILABLE:
        print("❌ Ollama not available!")
        print("Install: pip install ollama")
        print("Pull model: ollama pull gpt-oss:20b")
    else:
        asyncio.run(main())