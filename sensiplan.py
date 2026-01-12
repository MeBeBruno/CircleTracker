import math

class SensiplanEvaluator:
    def __init__(self, cycle_days):
        self.days = sorted(cycle_days, key=lambda x: x.date)

    def evaluate(self):
        valid_temps = [d for d in self.days if d.temperature is not None and not d.exclude_temp]
        
        result = {
            'is_fertile': True,
            'coverline': None,
            'ehM_day': None,
            'temp_eval_complete': False,
            'temp_complete_date': None,
            'mucus_peak_day': None,
            'mucus_eval_complete': False,
            'mucus_complete_date': None,
            'safe_from_date': None
        }

        # 1. Temperatur (3 über 6 Regel)
        if len(valid_temps) >= 9:
            for i in range(6, len(valid_temps)):
                candidate = valid_temps[i]
                prev_6 = valid_temps[i-6:i]
                coverline = max(d.temperature for d in prev_6)
                
                if candidate.temperature <= coverline: continue

                remaining = valid_temps[i+1:]
                if len(remaining) < 2: break 

                day_2 = remaining[0]
                day_3 = remaining[1]
                
                rule_1 = (day_2.temperature > coverline and day_3.temperature >= round(coverline + 0.2, 2))
                rule_ex1 = False
                rule_ex2 = False
                last_day = day_3

                if not rule_1 and len(remaining) >= 3:
                    day_4 = remaining[2]
                    # Ausnahme 1
                    if (day_2.temperature > coverline and day_3.temperature > coverline and day_4.temperature > coverline):
                        rule_ex1 = True
                        last_day = day_4
                    # Ausnahme 2
                    cond_drop = (day_2.temperature <= coverline or day_3.temperature <= coverline)
                    if not rule_ex1 and cond_drop and day_4.temperature >= round(coverline + 0.2, 2):
                        rule_ex2 = True
                        last_day = day_4

                if rule_1 or rule_ex1 or rule_ex2:
                    result['coverline'] = coverline
                    result['ehM_day'] = candidate.date
                    result['temp_eval_complete'] = True
                    result['temp_complete_date'] = last_day.date
                    break

        # 2. Schleim
        mucus_map = {'S+': 4, 'S': 3, 'f': 2, 'Ø': 1, 't': 0, None: -1}
        potential_peak = None
        
        for i in range(len(self.days) - 3):
            day = self.days[i]
            score = mucus_map.get(day.mucus_code, -1)
            
            if score >= 3:
                next_3 = self.days[i+1:i+4]
                if all(mucus_map.get(n.mucus_code, 0) < 3 for n in next_3):
                    potential_peak = day
                    result['mucus_complete_date'] = next_3[-1].date
        
        if potential_peak:
            result['mucus_peak_day'] = potential_peak.date
            result['mucus_eval_complete'] = True

        # 3. Gesamt
        if result['temp_eval_complete'] and result['mucus_eval_complete']:
            final_date = max(result['temp_complete_date'], result['mucus_complete_date'])
            result['safe_from_date'] = final_date

        return result