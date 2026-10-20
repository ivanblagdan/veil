//! Small score differences must remain distinct when choosing a label.
use veil_cli::decode;

#[test]
fn distinct_near_tie_logits_must_not_be_replaced_by_a_tie_or_tolerance() {
    let mut scores_by_label = [0.0; 35];
    scores_by_label[0] = 5.579_790_6;
    scores_by_label[18] = 5.579_785_3;
    assert!(scores_by_label[0] > scores_by_label[18]);
    assert!(scores_by_label[0] - scores_by_label[18] < 0.000_01);
    let (ids, scores) = decode(&scores_by_label, 35).unwrap();
    assert_eq!(ids, [0]);
    assert!(scores[0] > 0.4);

    scores_by_label[0] = 5.579_786_3;
    scores_by_label[18] = 5.579_797_3;
    let (ids, scores) = decode(&scores_by_label, 35).unwrap();
    assert_eq!(ids, [18]);
    assert!(scores[0] > 0.4);
}
