import pandas as pd
import joblib
from sklearn.model_selection import cross_val_score
from sklearn.tree import DecisionTreeClassifier

if __name__ == '__main__':
    print('Training Param Tampering Classifier\n')
    df = pd.read_json('../Dataset/pt_dataset.json')
    counts = df['label'].value_counts()
    print(counts)
    
    X = df['length'].to_numpy().astype(str)
    y = df['label'].to_numpy().astype(str)
    
    clf = DecisionTreeClassifier()
    cross_val_score(clf, X.reshape(-1, 1), y, cv=10)
    clf.fit(X.reshape(-1, 1), y)
    joblib.dump(clf, 'pt_predictor.joblib')
    print('\nModel trained and saved as pt_predictor.joblib')
