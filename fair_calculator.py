import numpy as np
from typing import Dict, Tuple

class FAIRCalculator:
    """
    FAIR (Factor Analysis of Information Risk) Calculator
    
    Calculates cybersecurity risk in dollar amounts using the FAIR framework.
    """
    
    def __init__(self, asset_value: float, threat_event_frequency: float, 
                 vulnerability: float, loss_magnitude: float):
        """
        Initialize FAIR calculator with risk parameters.
        
        Args:
            asset_value: Value of the asset at risk ($)
            threat_event_frequency: Expected threat events per year
            vulnerability: Probability of successful attack (0-1)
            loss_magnitude: Expected loss per incident ($)
        """
        self.asset_value = asset_value
        self.threat_event_frequency = threat_event_frequency
        self.vulnerability = vulnerability
        self.loss_magnitude = loss_magnitude
    
    def calculate_loss_event_frequency(self) -> float:
        """
        Calculate Loss Event Frequency (LEF)
        LEF = Threat Event Frequency (TEF) × Vulnerability
        """
        return self.threat_event_frequency * self.vulnerability
    
    def calculate_annual_loss_expectancy(self) -> float:
        """
        Calculate Annual Loss Expectancy (ALE)
        ALE = Loss Event Frequency × Loss Magnitude
        """
        lef = self.calculate_loss_event_frequency()
        return lef * self.loss_magnitude
    
    def calculate_single_loss_expectancy(self) -> float:
        """
        Calculate Single Loss Expectancy (SLE)
        SLE = Asset Value × Exposure Factor
        """
        return self.loss_magnitude
    
    def calculate_risk_level(self, ale: float) -> Dict[str, str]:
        """
        Categorize risk level based on ALE.
        
        Returns:
            Dict with risk level and color coding
        """
        if ale < 10000:
            return {'level': 'Low', 'color': 'green', 'priority': 'P4'}
        elif ale < 50000:
            return {'level': 'Medium', 'color': 'yellow', 'priority': 'P3'}
        elif ale < 200000:
            return {'level': 'High', 'color': 'orange', 'priority': 'P2'}
        else:
            return {'level': 'Critical', 'color': 'red', 'priority': 'P1'}
    
    def calculate(self) -> Dict:
        """
        Perform complete FAIR risk calculation.
        
        Returns:
            Dictionary with all calculated risk metrics
        """
        lef = self.calculate_loss_event_frequency()
        ale = self.calculate_annual_loss_expectancy()
        sle = self.calculate_single_loss_expectancy()
        risk_level = self.calculate_risk_level(ale)
        
        # Calculate risk exposure as percentage of asset value
        risk_exposure_pct = (ale / self.asset_value * 100) if self.asset_value > 0 else 0
        
        return {
            'asset_value': round(self.asset_value, 2),
            'threat_event_frequency': round(self.threat_event_frequency, 2),
            'vulnerability': round(self.vulnerability, 3),
            'loss_magnitude': round(self.loss_magnitude, 2),
            'loss_event_frequency': round(lef, 3),
            'single_loss_expectancy': round(sle, 2),
            'annual_loss_expectancy': round(ale, 2),
            'risk_level': risk_level['level'],
            'risk_color': risk_level['color'],
            'risk_priority': risk_level['priority'],
            'risk_exposure_percentage': round(risk_exposure_pct, 2)
        }
    
    def monte_carlo_simulation(self, tef_range: Tuple[float, float], 
                               vuln_range: Tuple[float, float],
                               loss_range: Tuple[float, float],
                               iterations: int = 10000) -> Dict:
        """
        Run Monte Carlo simulation for risk analysis.
        
        Args:
            tef_range: (min, max) for threat event frequency
            vuln_range: (min, max) for vulnerability
            loss_range: (min, max) for loss magnitude
            iterations: Number of simulation iterations
        
        Returns:
            Dictionary with simulation results and statistics
        """
        # Generate random samples
        tef_samples = np.random.uniform(tef_range[0], tef_range[1], iterations)
        vuln_samples = np.random.uniform(vuln_range[0], vuln_range[1], iterations)
        loss_samples = np.random.uniform(loss_range[0], loss_range[1], iterations)
        
        # Calculate ALE for each iteration
        lef_samples = tef_samples * vuln_samples
        ale_samples = lef_samples * loss_samples
        
        # Calculate statistics
        ale_mean = np.mean(ale_samples)
        ale_median = np.median(ale_samples)
        ale_std = np.std(ale_samples)
        ale_min = np.min(ale_samples)
        ale_max = np.max(ale_samples)
        
        # Calculate percentiles
        percentiles = {
            '10th': np.percentile(ale_samples, 10),
            '25th': np.percentile(ale_samples, 25),
            '50th': np.percentile(ale_samples, 50),
            '75th': np.percentile(ale_samples, 75),
            '90th': np.percentile(ale_samples, 90),
            '95th': np.percentile(ale_samples, 95),
            '99th': np.percentile(ale_samples, 99)
        }
        
        # Calculate risk level distribution
        low = np.sum(ale_samples < 10000)
        medium = np.sum((ale_samples >= 10000) & (ale_samples < 50000))
        high = np.sum((ale_samples >= 50000) & (ale_samples < 200000))
        critical = np.sum(ale_samples >= 200000)
        
        return {
            'iterations': iterations,
            'mean_ale': round(ale_mean, 2),
            'median_ale': round(ale_median, 2),
            'std_dev': round(ale_std, 2),
            'min_ale': round(ale_min, 2),
            'max_ale': round(ale_max, 2),
            'percentiles': {k: round(v, 2) for k, v in percentiles.items()},
            'risk_distribution': {
                'low': int(low),
                'medium': int(medium),
                'high': int(high),
                'critical': int(critical)
            },
            'confidence_95': {
                'lower': round(np.percentile(ale_samples, 2.5), 2),
                'upper': round(np.percentile(ale_samples, 97.5), 2)
            }
        }
