# Evaluation of profile status
def evaluate_profile_status(profile):
    score  = 0
    
    """
    Evaluate profile status:
    Total score = 10
    
    Conditions:
    >= 9: Excellent
    >= 7 Good
    >= 5: Average
    < 5: Incomplete
    """
    # Evaluate profile info fields
    if profile.full_name: score += 1
    if profile.position: score += 1
    if profile.summary: score += 1
    if profile.profile_image: score += 1
    if profile.phone or profile.linkedin or profile.github or \
        profile.portfolio or profile.other_link:
            score += 1
            
    # Evaluate the following models data
    if profile.educations.exists(): score += 1
    if profile.experiences.exists(): score += 1
    if profile.projects.exists(): score += 1
    if profile.skills.exists(): score += 1
    if profile.languages.exists(): score += 1
    
    # Calculate the score of profile
    if score >= 9:
        return "Excellent", "Amazing! Your profile is highly detailed and impressive."
    elif score >= 7:
        return "Good", "Nice! Your profile is attracting attention."
    elif score >= 5:
        return "Average", "Not bad, but you could improve your profile to stand out more."
    else:
        return "Incomplete", "Your profile needs more information. Fill out more sections to increase visibility."